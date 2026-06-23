//! In-memory event hub: one producer fans out to many subscribers without ever
//! blocking on a slow (or dead) one. growlightd's `subscribe` verb (spec §13
//! Observe) streams a subscriber's events over its socket; every future
//! producer (the agent stream-json tailer, the budget watcher, the scheduler's
//! leases, and — later — the coordination bus) publishes through this one seam.
//!
//! Design: a bounded [`std::sync::mpsc::sync_channel`] per subscriber.
//! [`EventHub::publish`] uses `try_send`, so a subscriber whose buffer is full
//! has the event DROPPED for it (it "lags") — the producer is never stalled and
//! the daemon never grows an unbounded backlog. This matches the observability
//! contract: the stream is best-effort live telemetry, not a durable log. There
//! is no async runtime in this workspace, so this is plain threads + channels.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use softfig_ipc::growlightd::Event;

/// Per-subscriber buffer depth. Generous enough to ride out a brief consumer
/// stall (e.g. a socket write momentarily blocking on a slow client), small
/// enough that a truly stuck subscriber can't pin meaningful memory. Overflow is
/// dropped, never queued.
pub const SUBSCRIBER_CAPACITY: usize = 256;

#[derive(Debug)]
struct Subscriber {
    id: u64,
    tx: SyncSender<Event>,
}

#[derive(Debug, Default)]
struct HubInner {
    subscribers: Vec<Subscriber>,
}

/// A cloneable handle to the shared event hub. Clones share one subscriber set,
/// so any holder can [`EventHub::publish`] and any holder can
/// [`EventHub::subscribe`].
#[derive(Debug, Clone)]
pub struct EventHub {
    inner: Arc<Mutex<HubInner>>,
    next_id: Arc<AtomicU64>,
}

impl EventHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner::default())),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Fan `event` out to every live subscriber. NEVER blocks: a subscriber
    /// whose buffer is full has this event dropped (it lags); a subscriber whose
    /// receiver has been dropped is pruned. The only lock taken is the brief one
    /// over the subscriber list — never a channel send that could wait on a
    /// consumer.
    pub fn publish(&self, event: Event) {
        let mut inner = self.inner.lock().unwrap();
        inner.subscribers.retain(|s| match s.tx.try_send(event.clone()) {
            Ok(()) => true,
            // Slow consumer: drop this event for it, but keep the subscription.
            Err(TrySendError::Full(_)) => true,
            // Receiver gone: prune it.
            Err(TrySendError::Disconnected(_)) => false,
        });
    }

    /// Register a new subscriber and return its [`Subscription`]. Dropping the
    /// subscription deregisters it (and the next `publish` would prune it anyway
    /// once its receiver is gone).
    pub fn subscribe(&self) -> Subscription {
        let (tx, rx) = sync_channel(SUBSCRIBER_CAPACITY);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .lock()
            .unwrap()
            .subscribers
            .push(Subscriber { id, tx });
        Subscription {
            id,
            rx,
            inner: Arc::clone(&self.inner),
        }
    }

    /// Number of live subscribers. Useful for `status` and to let a test wait
    /// until a socket-side subscription has registered before it publishes.
    pub fn subscriber_count(&self) -> usize {
        self.inner.lock().unwrap().subscribers.len()
    }
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

/// The consumer end of one subscription. The `subscribe` handler owns one per
/// connection and forwards its events over the socket; tests own one directly.
/// Dropping it removes the subscription from the hub.
#[derive(Debug)]
pub struct Subscription {
    id: u64,
    rx: Receiver<Event>,
    inner: Arc<Mutex<HubInner>>,
}

impl Subscription {
    /// Block up to `timeout` for the next event. The streaming server uses a
    /// short timeout so it can periodically re-check the daemon's `Stopping`
    /// flag between events.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Non-blocking poll for a buffered event.
    pub fn try_recv(&self) -> Result<Event, TryRecvError> {
        self.rx.try_recv()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.subscribers.retain(|s| s.id != self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::growlightd::AgentDeltaKind;
    use std::thread;

    fn delta(i: usize) -> Event {
        Event::agent_delta("a1", AgentDeltaKind::Assistant, format!("d{i}"))
    }

    #[test]
    fn deltas_reach_a_subscriber_in_order() {
        let hub = EventHub::new();
        let sub = hub.subscribe();
        for i in 0..5 {
            hub.publish(delta(i));
        }
        for i in 0..5 {
            assert_eq!(sub.try_recv().unwrap(), delta(i));
        }
        assert!(sub.try_recv().is_err(), "no extra events buffered");
    }

    #[test]
    fn fan_out_every_subscriber_gets_every_event() {
        let hub = EventHub::new();
        let a = hub.subscribe();
        let b = hub.subscribe();
        let c = hub.subscribe();
        assert_eq!(hub.subscriber_count(), 3);
        for i in 0..10 {
            hub.publish(delta(i));
        }
        for sub in [&a, &b, &c] {
            for i in 0..10 {
                assert_eq!(sub.try_recv().unwrap(), delta(i));
            }
        }
    }

    /// The key invariant: a subscriber that never drains must not stall — or
    /// deadlock — the producer. We publish far more than one buffer's worth into
    /// an undrained subscriber and require the producer thread to finish well
    /// within a timeout (a blocking send would hang it forever).
    #[test]
    fn slow_subscriber_never_stalls_the_producer() {
        let hub = EventHub::new();
        let slow = hub.subscribe(); // intentionally never drained → its buffer fills
        let total = SUBSCRIBER_CAPACITY * 8;

        let producer = hub.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let h = thread::spawn(move || {
            for i in 0..total {
                producer.publish(delta(i));
            }
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("producer must never stall on a slow subscriber");
        h.join().unwrap();

        // Drop policy: a bounded buffer's worth was kept, the overflow dropped —
        // never an unbounded backlog, never a block.
        let mut got = 0;
        while slow.try_recv().is_ok() {
            got += 1;
        }
        assert!(got > 0, "slow subscriber still received some events");
        assert!(got <= SUBSCRIBER_CAPACITY, "slow buffer stays bounded ({got})");
        assert!(got < total, "slow subscriber dropped the overflow ({got})");
    }

    #[test]
    fn dropping_a_subscription_deregisters_it() {
        let hub = EventHub::new();
        let a = hub.subscribe();
        {
            let _b = hub.subscribe();
            assert_eq!(hub.subscriber_count(), 2);
        }
        assert_eq!(hub.subscriber_count(), 1);
        drop(a);
        assert_eq!(hub.subscriber_count(), 0);
    }

    #[test]
    fn a_dead_subscriber_does_not_block_a_live_one() {
        let hub = EventHub::new();
        let live = hub.subscribe();
        let gone = hub.subscribe();
        drop(gone);
        for i in 0..3 {
            hub.publish(delta(i));
        }
        for i in 0..3 {
            assert_eq!(live.try_recv().unwrap(), delta(i));
        }
        assert_eq!(hub.subscriber_count(), 1);
    }
}
