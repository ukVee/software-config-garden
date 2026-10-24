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
pub mod agent_harness;
pub mod backend_router;
pub mod baton_store;
pub mod bus;
pub mod claim;
pub mod claude_backend;
pub mod config;
pub mod control;
pub mod daemon;
pub mod drive_loop;
pub mod fleet;
pub mod handshake;
pub mod hub;
pub mod leases;
pub mod member_handoff;
pub mod member_slices;
pub mod member_verbs;
pub mod notifications;
pub mod notify_dispatch;
pub mod opencode_backend;
pub mod opencode_ledger;
pub mod opencode_preapproval;
pub mod peer;
pub mod persist;
pub mod preapproval;
pub mod profile_budget;
pub mod profile_pin;
pub mod queue_source;
pub mod rate_limit_holds;
pub mod reconcile;
pub mod resume;
pub mod scheduler;
pub mod scheduler_v2;
pub mod server;
pub mod state;
pub mod supervisor;
pub mod thrash_bridge;
pub mod usage;
pub mod usage_file;
pub mod v2_source;

pub use admission::{
    AdmissionDecision, AdmissionGovernor, BudgetUsage, Intent, RateState, RefuseReason,
};
pub use backend_router::{BackendHandle, BackendRouter};
pub use baton_store::{FsBatonStore, FsEntryBatonStore};
pub use bus::{spawn_bus_tailer, BusBridge, BusError, BusSource, KeeperdBusSource, BUS_POLL_MS};
pub use claim::KeeperdPartClaimer;
pub use agent_harness::{AgentHealthState, BackendFlavor, Harness, LineObserver};
pub use claude_backend::ClaudeBackend;
pub use config::{BuildCaps, GrowlightdConfig, Policy};
pub use control::{AgentChild, Control};
pub use daemon::{Daemon, DaemonHandle, GrowlightdError};
pub use drive_loop::{
    spawn_drive_loop, AgentHealthSource, AgentStderrSource, Assignment, BatonRead, BatonSeeder,
    BatonStatusSource, BudgetSampleSource, DeferredBatonSeeder, DeferredBatonStatus,
    DeferredQueues, DriveLoop, FleetMember, HeldPart, HeldStart, NoRepoProbe, PartClaimer,
    PermissiveRate, QueueSource, RateMeter, RateSource, RepoProbe, TickReport, DRIVE_POLL_MS,
};
pub use fleet::{
    assemble_fleet, load_fleet_config, spawn_fleet, FleetConfig, FleetMemberConfig, MemberBackend,
    QueueMode, DEFAULT_CLAUDE_BIN, DEFAULT_OPENCODE_BIN, DEFAULT_PROMPT,
};
pub use handshake::{garden_root_via_keeperd, HandshakeError};
pub use hub::{EventHub, Subscription};
pub use leases::{LeaseDecision, LeaseTable, ReleaseOutcome, ThrashClear};
pub use notifications::{Channel, NotifyEvent, NotifyPolicy};
pub use notify_dispatch::{
    BusEmit, GuiNotifier, KeeperdBusEmit, LogNotifier, LogSink, Notifier, NotifyDispatcher,
    PhoneStub, StderrLog, ALERT_FROM, ALERT_KIND,
};
pub use opencode_backend::{AgentSpend, ModelSelection, OpencodeBackend, OpencodeLaunch};
pub use opencode_preapproval::OpencodePreApproval;
pub use persist::{KeeperdResourcePersister, ResourcePersister};
pub use preapproval::{agent_paths, AgentPaths, GenError, PreApproval, ALLOW};
pub use profile_budget::{
    headroom_from, pool_headroom, profile_budget_path, read_profile_budget, slot_headroom,
    Headroom, STALE_FLOOR_SECS,
};
pub use profile_pin::{
    pick_round_robin, pick_with_budget, pin_paths, read_pin, read_pin_history, write_pin, PickResult,
    PinPaths, ProfilePin, HEADROOM_STALL_PCT, HEADROOM_WARN_PCT,
};
pub use queue_source::{
    parse_snapshot, KeeperdQueueSource, KeeperdRepoProbe, BACKLOG_DOC, DEFAULT_QUEUE_NAME,
};
pub use reconcile::{reconcile_on_boot, ReconcileReport};
pub use resume::{ItemResumer, KeeperdItemResumer, ResumeOutcome};
pub use scheduler::{
    classify_queue, held, parked, pick, pick_for, ClaimHold, PartStatus, PartView, QueueState,
    QueueView, Snapshot,
};
pub use state::State;
pub use supervisor::{
    AgentBackend, AgentHealth, AgentSpec, Backoff, PollOutcome, RerollOutcome, SpawnError,
    StartOutcome, Supervisor,
};
pub use thrash_bridge::{parse_target, KeeperThrashClear, TargetClear};
pub use usage::{
    usage_alert_reached, UsageAggregator, UsageSample, WindowResets, USAGE_ALERT_PCT,
};
pub use v2_source::{assemble, V2Load, V2Source, V2SourceError};
