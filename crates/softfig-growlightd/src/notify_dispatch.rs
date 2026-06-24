//! Notification **dispatch** (phase 5, slice 002) — the swappable channel seam
//! that delivers the policy engine's decisions (spec-growlight-orchestrator §9,
//! alerts also §4a).
//!
//! ## What this is (and isn't)
//!
//! The pure router lives next door in [`crate::notifications`]:
//! [`NotifyPolicy::decide`]`(event, now)` answers *which channels fire?* with no
//! I/O. This module is the **delivery** half — a [`Notifier`] trait per channel,
//! three impls (a GUI-stream notifier, an audit-log notifier, an inert phone
//! stub), and a [`NotifyDispatcher`] that runs the policy and fans a fired alert
//! to every registered notifier the policy selected. Keeping delivery separate
//! from the policy keeps the policy provable in isolation and keeps each
//! transport thin (it only renders [`NotifyEvent::summary`], never re-decides).
//!
//! ## The two "buses" an alert touches (don't conflate them)
//!
//! 1. The **GUI subscribe stream** (in-process [`EventHub`], §11) — best-effort
//!    live telemetry to subscribed clients. The [`GuiNotifier`] publishes each
//!    fired alert here as an [`Event::BusMessage`] with `kind == "alert"`: the
//!    coordination bus already renders to this same stream, and "an alert is just
//!    `kind == \"alert\"`" (see [`Event::bus_message`]). This is wired live now.
//! 2. The **committed coordination bus** (keeperd's `growlight/chat/` store, §4a)
//!    — alerts also persist there as `kind: alert`. Posting to it needs a
//!    growlightd→keeperd *write*, but the bus bridge is one-way
//!    growlightd-**pulls**-from-keeperd (LOCKED — [`crate::bus`]); no post verb
//!    exists yet. So [`BusEmit`] is a **default-absent seam** (mirroring
//!    [`crate::leases::ThrashClear`]'s deferred `clear_flag` binding): proven here
//!    against a spy, its live binding deferred to the phase-6 drive loop.

use std::fmt;
use std::sync::Mutex;

use softfig_ipc::growlightd::Event;

use crate::hub::EventHub;
use crate::notifications::{Channel, NotifyEvent, NotifyPolicy};

/// The message class every alert carries on the subscribe stream and (later) the
/// committed bus — §4a: "alerts ride the bus as `kind: alert`".
pub const ALERT_KIND: &str = "alert";

/// growlightd's own bus address as the sender of an alert.
pub const ALERT_FROM: &str = "growlightd";

// ---------------------------------------------------------------------------
// The channel seam.
// ---------------------------------------------------------------------------

/// One delivery transport, bound to a single [`Channel`]. The dispatcher holds a
/// registry of these and calls [`deliver`](Notifier::deliver) on each whose
/// [`channel`](Notifier::channel) the policy selected. `Send + Sync + Debug`
/// because the daemon shares the dispatcher across connection threads (the
/// [`crate::leases::ThrashClear`] / [`crate::bus::BusSource`] seam shape).
pub trait Notifier: Send + Sync + fmt::Debug {
    /// Which channel this notifier serves.
    fn channel(&self) -> Channel;
    /// Deliver a fired alert. [`NotifyEvent::summary`] is the human-facing body;
    /// the impl renders it for its medium. Called only when the policy selected
    /// this notifier's channel for a fresh (non-suppressed) fire.
    fn deliver(&self, event: &NotifyEvent);
}

/// The §4a committed-bus emission hook: post a fired alert to keeperd's
/// `growlight/chat/` store as a `kind: alert` message. **Default-absent** — the
/// bus bridge is one-way (growlightd pulls; no growlightd→keeperd post verb yet,
/// LOCKED), so the live binding lands with the phase-6 drive loop, exactly like
/// [`crate::leases::ThrashClear`]. Proven here against a spy.
pub trait BusEmit: Send + Sync + fmt::Debug {
    /// Post `event` to the coordination bus as a `kind: alert` message.
    fn emit_alert(&self, event: &NotifyEvent);
}

// ---------------------------------------------------------------------------
// GUI-stream notifier (wired live).
// ---------------------------------------------------------------------------

/// The GUI channel: fans each fired alert onto growlightd's `subscribe` event
/// hub as an [`Event::BusMessage`] with `kind == "alert"` (the §9 alert hook
/// rides the same stream the coordination bus renders to). The human-attention
/// set ([`NotifyEvent::is_human_attention`]) is addressed `to: "human"`; the
/// rest broadcast `to: "all"` — matching the bus' `@`-stripped address form.
#[derive(Debug, Clone)]
pub struct GuiNotifier {
    hub: EventHub,
}

impl GuiNotifier {
    pub fn new(hub: EventHub) -> Self {
        Self { hub }
    }
}

impl Notifier for GuiNotifier {
    fn channel(&self) -> Channel {
        Channel::Gui
    }

    fn deliver(&self, event: &NotifyEvent) {
        let to = if event.is_human_attention() { "human" } else { "all" };
        self.hub
            .publish(Event::bus_message(ALERT_FROM, to, ALERT_KIND, event.summary()));
    }
}

// ---------------------------------------------------------------------------
// Audit-log notifier (wired live, through an injectable sink).
// ---------------------------------------------------------------------------

/// Where the [`LogNotifier`] writes its durable line. Production is
/// [`StderrLog`] (stderr → the systemd journal, this crate's logging idiom);
/// tests inject a recording spy. The seam keeps "the log channel received the
/// alert" observable without scraping stderr.
pub trait LogSink: Send + Sync + fmt::Debug {
    /// Append one already-formatted audit line.
    fn write_line(&self, line: &str);
}

/// Production [`LogSink`]: the durable record is stderr, captured by the journal
/// (growlightd has no structured logger — `eprintln!` is the idiom).
#[derive(Debug, Default, Clone, Copy)]
pub struct StderrLog;

impl LogSink for StderrLog {
    fn write_line(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// The audit-log channel: writes a durable one-line record of each fired alert
/// through its [`LogSink`]. Always fires (§9), so this is the alert history of
/// record independent of any GUI client being attached.
#[derive(Debug)]
pub struct LogNotifier<S: LogSink> {
    sink: S,
}

impl<S: LogSink> LogNotifier<S> {
    pub fn new(sink: S) -> Self {
        Self { sink }
    }
}

impl LogNotifier<StderrLog> {
    /// The production notifier: logs to stderr.
    pub fn stderr() -> Self {
        Self::new(StderrLog)
    }
}

impl<S: LogSink> Notifier for LogNotifier<S> {
    fn channel(&self) -> Channel {
        Channel::Log
    }

    fn deliver(&self, event: &NotifyEvent) {
        self.sink
            .write_line(&format!("growlightd alert: {}", event.summary()));
    }
}

// ---------------------------------------------------------------------------
// Phone stub (inert — the real BLE/RFCOMM peer is the held phone-peer milestone).
// ---------------------------------------------------------------------------

/// The phone channel — an **inert stub**. Selectable behind the same [`Notifier`]
/// seam so the dispatcher routes human-attention alerts to it today, but
/// delivery does no live I/O: the real transport is BLE/RFCOMM to the
/// postmarketOS phone peer (the held phone-peer milestone). Deliveries are
/// *recorded* (not sent) so a test can prove the routing reached the phone
/// channel while the wire stays dark.
#[derive(Debug, Default)]
pub struct PhoneStub {
    delivered: Mutex<Vec<String>>,
}

impl PhoneStub {
    pub fn new() -> Self {
        Self::default()
    }

    /// The summaries routed to the phone so far (recorded-only — nothing was sent
    /// over any radio). Used by tests/observability to confirm selection.
    pub fn delivered(&self) -> Vec<String> {
        self.delivered.lock().unwrap().clone()
    }
}

impl Notifier for PhoneStub {
    fn channel(&self) -> Channel {
        Channel::Phone
    }

    fn deliver(&self, event: &NotifyEvent) {
        // No radio yet — record that the alert WOULD be sent, then return.
        self.delivered.lock().unwrap().push(event.summary());
    }
}

// ---------------------------------------------------------------------------
// The dispatcher.
// ---------------------------------------------------------------------------

/// The notification dispatcher: the pure [`NotifyPolicy`] plus a registry of
/// channel [`Notifier`]s and the optional [`BusEmit`] hook. On each orchestrator
/// event, [`notify`](Self::notify) runs the policy and fans the fired alert to
/// every registered notifier whose channel the policy selected; a suppressed
/// (cooldown) event delivers to nothing. The daemon owns one and wires its
/// channels at startup (the live event producers arrive with the phase-6 drive
/// loop — this slice builds and proves the seam, additively).
#[derive(Debug)]
pub struct NotifyDispatcher {
    policy: NotifyPolicy,
    notifiers: Vec<Box<dyn Notifier>>,
    bus: Option<Box<dyn BusEmit>>,
}

impl NotifyDispatcher {
    /// A dispatcher with the default policy and no channels registered yet.
    pub fn new() -> Self {
        Self::with_policy(NotifyPolicy::new())
    }

    /// A dispatcher over an explicit policy (the test seam uses a short-cooldown
    /// [`NotifyPolicy::with_cooldown`]).
    pub fn with_policy(policy: NotifyPolicy) -> Self {
        Self {
            policy,
            notifiers: Vec::new(),
            bus: None,
        }
    }

    /// Register a channel notifier. Several notifiers may serve the same channel
    /// (all of them then receive that channel's alerts).
    pub fn register(&mut self, notifier: Box<dyn Notifier>) {
        self.notifiers.push(notifier);
    }

    /// Deregister every notifier serving `channel`. Returns how many were
    /// removed, so a caller can tell a real teardown from a no-op.
    pub fn deregister(&mut self, channel: Channel) -> usize {
        let before = self.notifiers.len();
        self.notifiers.retain(|n| n.channel() != channel);
        before - self.notifiers.len()
    }

    /// Bind the §4a committed-bus emission hook (default none → no live post).
    pub fn set_bus_emit(&mut self, bus: Box<dyn BusEmit>) {
        self.bus = Some(bus);
    }

    /// Number of registered notifiers serving `channel` (for `status`/tests).
    pub fn notifier_count(&self, channel: Channel) -> usize {
        self.notifiers
            .iter()
            .filter(|n| n.channel() == channel)
            .count()
    }

    /// Route `event` at `now` (Unix seconds): run [`NotifyPolicy::decide`], then
    /// — on a fresh fire — deliver to each registered notifier whose channel is
    /// in the decided set and emit the `kind: alert` bus message via the
    /// [`BusEmit`] hook (if bound). A suppressed event (empty decided set)
    /// delivers to nothing and posts nothing. Returns the decided channel set
    /// (for observability/tests); empty means suppressed.
    pub fn notify(&mut self, event: &NotifyEvent, now: i64) -> Vec<Channel> {
        let channels = self.policy.decide(event, now);
        if channels.is_empty() {
            return channels;
        }
        for notifier in &self.notifiers {
            if channels.contains(&notifier.channel()) {
                notifier.deliver(event);
            }
        }
        if let Some(bus) = &self.bus {
            bus.emit_alert(event);
        }
        channels
    }
}

impl Default for NotifyDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A recording [`LogSink`] — captures the lines the audit-log notifier wrote.
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

    /// A recording [`BusEmit`] — proves the deferred committed-bus seam is
    /// exercised on a fresh fire (its live keeperd binding is phase 6).
    #[derive(Debug, Default)]
    struct SpyBus {
        posted: Mutex<Vec<(String, String)>>, // (kind-implied "alert", body)
    }
    impl SpyBus {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        fn bodies(&self) -> Vec<String> {
            self.posted.lock().unwrap().iter().map(|(_, b)| b.clone()).collect()
        }
    }
    impl BusEmit for Arc<SpyBus> {
        fn emit_alert(&self, event: &NotifyEvent) {
            self.posted
                .lock()
                .unwrap()
                .push((ALERT_KIND.to_string(), event.summary()));
        }
    }

    /// A low-priority event (gui/log only, never the phone) — for tests that
    /// exercise the @all broadcast / no-phone delivery paths.
    fn slice_done() -> NotifyEvent {
        NotifyEvent::SliceComplete {
            part: "001".to_string(),
        }
    }
    fn blocked(item: &str) -> NotifyEvent {
        NotifyEvent::BlockedOnHuman {
            item: item.to_string(),
        }
    }

    /// A fired alert reaches the GUI stream (as `Event::BusMessage{kind:"alert"}`)
    /// and the audit log, carrying the event's summary as the body/line.
    #[test]
    fn a_fired_alert_reaches_gui_and_log() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let spy = SpyLog::new();

        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.register(Box::new(GuiNotifier::new(hub)));
        d.register(Box::new(LogNotifier::new(Arc::clone(&spy))));

        let chans = d.notify(&slice_done(), 0);
        assert_eq!(chans, vec![Channel::Gui, Channel::Log]);

        // GUI: a kind:"alert" bus message addressed @all (slice-complete is not
        // human-attention).
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::bus_message(ALERT_FROM, "all", ALERT_KIND, "slice `001` complete")
        );
        assert!(sub.try_recv().is_err(), "exactly one GUI event");
        // Log: one durable audit line carrying the same summary.
        assert_eq!(spy.lines(), vec!["growlightd alert: slice `001` complete".to_string()]);
    }

    /// A human-attention alert is additionally addressed `to: "human"` on the GUI
    /// stream and routed to the phone stub; the stub records it but sends nothing.
    #[test]
    fn human_attention_alert_addresses_human_and_routes_to_the_inert_phone() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let phone = Arc::new(PhoneStub::new());

        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.register(Box::new(GuiNotifier::new(hub)));
        // The dispatcher owns a Box<dyn Notifier>; keep an Arc handle to inspect.
        struct PhoneRef(Arc<PhoneStub>);
        impl fmt::Debug for PhoneRef {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("PhoneRef")
            }
        }
        impl Notifier for PhoneRef {
            fn channel(&self) -> Channel {
                Channel::Phone
            }
            fn deliver(&self, event: &NotifyEvent) {
                self.0.deliver(event)
            }
        }
        d.register(Box::new(PhoneRef(Arc::clone(&phone))));

        let chans = d.notify(&blocked("004"), 0);
        assert_eq!(chans, vec![Channel::Gui, Channel::Log, Channel::Phone]);
        assert_eq!(
            sub.try_recv().unwrap(),
            Event::bus_message(ALERT_FROM, "human", ALERT_KIND, "`004` is blocked on a human decision")
        );
        // The phone was selected and recorded the delivery — but sent nothing.
        assert_eq!(phone.delivered(), vec!["`004` is blocked on a human decision".to_string()]);
    }

    /// A non-human-attention event never routes to the phone, even when a phone
    /// notifier is registered.
    #[test]
    fn low_priority_event_does_not_route_to_the_phone() {
        let phone = Arc::new(PhoneStub::new());
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        struct PhoneRef(Arc<PhoneStub>);
        impl fmt::Debug for PhoneRef {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("PhoneRef")
            }
        }
        impl Notifier for PhoneRef {
            fn channel(&self) -> Channel {
                Channel::Phone
            }
            fn deliver(&self, event: &NotifyEvent) {
                self.0.deliver(event)
            }
        }
        d.register(Box::new(PhoneRef(Arc::clone(&phone))));

        let chans = d.notify(&slice_done(), 0); // slice-complete → gui/log only
        assert_eq!(chans, vec![Channel::Gui, Channel::Log]);
        assert!(phone.delivered().is_empty(), "phone not selected for a low-priority event");
    }

    /// A suppressed (cooldown) event delivers to nothing and posts nothing to the
    /// bus seam — the §9 dedup, observed through delivery, not just the policy.
    #[test]
    fn a_suppressed_event_delivers_to_nothing() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let spy = SpyLog::new();
        let bus = SpyBus::new();

        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.register(Box::new(GuiNotifier::new(hub)));
        d.register(Box::new(LogNotifier::new(Arc::clone(&spy))));
        d.set_bus_emit(Box::new(Arc::clone(&bus)));

        // First fire delivers everywhere.
        assert_eq!(d.notify(&slice_done(), 0), vec![Channel::Gui, Channel::Log]);
        let _ = sub.try_recv().unwrap();
        assert_eq!(spy.lines().len(), 1);
        assert_eq!(bus.bodies().len(), 1);

        // Inside the cooldown → suppressed: nothing new anywhere.
        assert!(d.notify(&slice_done(), 50).is_empty(), "suppressed");
        assert!(sub.try_recv().is_err(), "no GUI event on a suppressed fire");
        assert_eq!(spy.lines().len(), 1, "no extra log line");
        assert_eq!(bus.bodies().len(), 1, "no extra bus post");
    }

    /// Deregistration changes who receives: drop the log channel and only the GUI
    /// notifier still delivers.
    #[test]
    fn registration_and_deregistration_change_who_receives() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        let spy = SpyLog::new();

        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.register(Box::new(GuiNotifier::new(hub)));
        d.register(Box::new(LogNotifier::new(Arc::clone(&spy))));
        assert_eq!(d.notifier_count(Channel::Log), 1);

        assert_eq!(d.deregister(Channel::Log), 1, "one log notifier removed");
        assert_eq!(d.deregister(Channel::Log), 0, "deregister is idempotent");
        assert_eq!(d.notifier_count(Channel::Log), 0);

        // A fresh identity fires: GUI delivers, the deregistered log does not.
        let chans = d.notify(&NotifyEvent::Usage, 0);
        assert!(chans.contains(&Channel::Gui) && chans.contains(&Channel::Log));
        assert!(sub.try_recv().is_ok(), "GUI still receives");
        assert!(spy.lines().is_empty(), "the deregistered log channel receives nothing");
    }

    /// The deferred committed-bus seam fires on a fresh alert and is absent by
    /// default (no panic, delivery still works without a bus binding).
    #[test]
    fn bus_emit_seam_fires_on_a_fresh_alert_and_is_optional() {
        // Default: no bus hook bound → notify still delivers, posts nothing.
        let mut d0 = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        let spy0 = SpyLog::new();
        d0.register(Box::new(LogNotifier::new(Arc::clone(&spy0))));
        assert!(!d0.notify(&blocked("004"), 0).is_empty());
        assert_eq!(spy0.lines().len(), 1, "delivery works with no bus hook");

        // Bound: a fresh fire emits the kind:alert bus message with the summary.
        let bus = SpyBus::new();
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::with_cooldown(100));
        d.set_bus_emit(Box::new(Arc::clone(&bus)));
        d.notify(&blocked("004"), 0);
        assert_eq!(bus.bodies(), vec!["`004` is blocked on a human decision".to_string()]);
    }
}
