//! Daemon state machine. The state guards which verbs are answerable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Vault is locked. Only `status` and `unlock` are answerable.
    Locked,
    /// Vault is unlocked; full verb set available.
    Unlocked,
    /// Shutdown initiated; accept loop wraps up after the in-flight
    /// connection drains.
    Stopping,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Unlocked => "unlocked",
            Self::Stopping => "stopping",
        }
    }
}
