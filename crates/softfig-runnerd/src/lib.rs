//! `softfig-runnerd` — the soft-fig remote runner daemon.
//!
//! A **system** service under its own `softfig-runner` uid that runs sandboxed
//! build/test jobs for a paired requester (spec `remote-runner`). It holds a
//! delegated runner key — an X25519 transport static and an Ed25519 attest key,
//! bound to the device by a certificate the device identity signs
//! (`softfig-net::runner_cert`) — and an `accept.toml` allowlist of requesters
//! written through an admin unix socket that only the owner uid may connect to.
//!
//! **Deliberately vault-free.** runnerd never links `softfig-vault` and never
//! reads a garden, so it keeps serving while the garden is locked, and an
//! escape lands in an account that cannot reach the owner's data. This crate's
//! dependency set is bounded to that end — keys, config, and a gated socket,
//! nothing that can sign commits or read a chain.
//!
//! This slice (002) stands up the identity + install skeleton: key generation,
//! the `serve.toml`/`accept.toml` types, and the `SO_PEERCRED` admin socket.
//! Job transport, sandboxing, and the full verb set land in later slices.

#![deny(unsafe_code)]

pub mod admin;
pub mod attestation;
pub mod cert;
pub mod config;
pub mod daemon;
pub mod error;
pub mod executor;
pub mod fetch;
pub mod jobs;
pub mod keys;
pub mod log;
pub mod proxy;
pub mod state;
pub mod systemd;
pub mod wire;

pub use admin::{
    call as admin_call, require_owner_uid, serve_connection, AdminClient, AdminRequest,
    AdminResponse, AdminSocket, ApplyArgs, GrantArgs, GrantReply, RevokeArgs, RevokeCertArgs,
    RevokeReply, StoreCertArgs,
};
pub use attestation::{
    ArtifactEntry, EnvBinding, ExitInfo, JobAttestation, SignedAttestation, SourceRef,
    ToolchainInfo, ATTEST_DOMAIN,
};
pub use cert::{StoredCert, StoredRevocation};
pub use config::{AcceptConfig, AcceptedPeer, BatteryCaps, ServeConfig};
pub use error::{Error, Result};
pub use executor::{parse_duration, parse_size, Artifact, RunOutcome, SandboxBinaries};
pub use fetch::{toolchain_add_command, toolchain_missing};
pub use jobs::{append_ndjson, Job, JobRecord, JobTable};
pub use keys::RunnerKeys;
pub use log::{read_framed_chunks, write_framed_chunk, DEFAULT_LOG_RING_BYTES, JobLogs, LogChunk, LogSink};
pub use proxy::{host_allowed, EgressProxy};
pub use state::{StateRoot, DEFAULT_STATE_ROOT};
pub use systemd::{
    battery_reject, on_battery, run_unit, stop_unit, unit_name, Caps, CapsHit, EnvSpec,
    JobReport, JobSpec, Manager, UnitResult, CANCELLED_EXIT, OOM_EXIT, POWER_SUPPLY_PATH,
    TIMEOUT_EXIT,
};
pub use wire::WireServer;
