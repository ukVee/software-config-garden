//! growlightd's lifecycle state. Far simpler than keeperd's (no vault to
//! lock/unlock) — the daemon is either serving or winding down.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Serving clients and (in later phases) supervising the fleet.
    Running,
    /// Shutdown initiated; the accept loop exits after the in-flight
    /// connection drains.
    Stopping,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopping => "stopping",
        }
    }
}
