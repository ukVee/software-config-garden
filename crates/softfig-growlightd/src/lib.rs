//! soft-fig multi-agent orchestrator daemon (growlightd).
//!
//! The supervised control-plane daemon that owns the agent fleet and exposes
//! one IPC surface its clients (CLI, iced GUI, phone) render — the keystone of
//! `meta/spec-growlight-orchestrator.md` (§2). It is a keeperd *client* (reaches
//! the garden through keeperd/MCP) **and** an agent supervisor **and** a server
//! for its own clients, kept a separate process from keeperd so vault security
//! never shares a fate with agent-orchestration crashes.
//!
//! Phase 1 (this milestone) stands up the daemon, its socket, the keeperd
//! `status` handshake, and per-device policy — no agents yet. The fleet,
//! coordination bus, scheduler, and admission governor arrive in later phases.
//!
//! Library entry: [`Daemon::start`] binds the socket and returns a handle that
//! owns the accept loop. The handle can be `join()`ed for blocking mode
//! (`softfig-growlightd`) or driven by tests in-process.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod admission;
pub mod bus;
pub mod claude_backend;
pub mod config;
pub mod control;
pub mod daemon;
pub mod handshake;
pub mod hub;
pub mod leases;
pub mod notifications;
pub mod notify_dispatch;
pub mod peer;
pub mod scheduler;
pub mod server;
pub mod state;
pub mod supervisor;
pub mod usage;

pub use admission::{
    AdmissionDecision, AdmissionGovernor, BudgetUsage, Intent, RateState, RefuseReason,
};
pub use bus::{spawn_bus_tailer, BusBridge, BusError, BusSource, KeeperdBusSource, BUS_POLL_MS};
pub use claude_backend::{AgentHealthState, ClaudeBackend};
pub use config::{GrowlightdConfig, Policy};
pub use control::{AgentChild, Control};
pub use daemon::{Daemon, DaemonHandle, GrowlightdError};
pub use handshake::{garden_root_via_keeperd, HandshakeError};
pub use hub::{EventHub, Subscription};
pub use leases::{LeaseDecision, LeaseTable, ReleaseOutcome, ThrashClear};
pub use notifications::{Channel, NotifyEvent, NotifyPolicy, UsageLevel};
pub use notify_dispatch::{
    BusEmit, GuiNotifier, LogNotifier, LogSink, Notifier, NotifyDispatcher, PhoneStub, StderrLog,
    ALERT_FROM, ALERT_KIND,
};
pub use scheduler::{
    classify_queue, parked, pick, PartStatus, PartView, QueueState, QueueView, Snapshot,
};
pub use state::State;
pub use supervisor::{
    AgentBackend, AgentHealth, AgentSpec, Backoff, PollOutcome, RerollOutcome, SpawnError,
    StartOutcome, Supervisor,
};
pub use usage::{levels_reached, UsageAggregator, UsageSample};
