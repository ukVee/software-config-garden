//! The seam a capture point hands rows to.

use crate::row::RequestRow;

/// Takes one [`RequestRow`] per API request. Called from a member's stdout
/// reader thread, once per closed request, so an implementation must not block
/// and must do no I/O: the production one ([`RingRecorder`](crate::RingRecorder)) pushes into a
/// bounded buffer that a separate flush thread drains.
pub trait Recorder: Send + Sync {
    fn record(&self, row: RequestRow);
}

/// Drops every row: for tests that don't assert telemetry, and for a daemon
/// whose telemetry store could not be opened (a member never fails over its
/// accounting).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullRecorder;

impl Recorder for NullRecorder {
    fn record(&self, _row: RequestRow) {}
}
