//! soft-fig sandbox engine.
//!
//! One [`Policy`] renders into a deterministic `bubblewrap` (bwrap) argv; the
//! companion exec shim `softfig-sandbox-init` then applies a Landlock ruleset
//! and a seccomp filter derived from the *same* bind list, and execs the
//! command.
//!
//! The same policy engine backs both the remote runner's per-job sandboxes
//! ([[spec-remote-runner]] §7.1) and the fleet safety-order step 4 member
//! sandbox, so it is deliberately backend- and runner-neutral: it knows nothing
//! about git, cargo, or the runner lifecycle.
//!
//! Layer split (spec §7.1 "no single layer is the boundary; the stack is"):
//! 1. a separate uid (the runner's `softfig-runner`);
//! 2. a transient systemd unit per job (cgroup caps);
//! 3. bubblewrap — this crate's [`Policy::render`];
//! 4. Landlock — the init shim, from the same bind list ([`Policy::fs_rules`]);
//! 5. seccomp — the init shim ([`build_seccomp_filter`]), chosen over bwrap
//!    `--seccomp <fd>` so the argv stays a pure, deterministic `Vec<String>`
//!    and no FD number is inherited.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod policy;
mod profiles;
mod seccomp;

pub use policy::{Bind, BindMode, FsRule, Network, Policy, ProxyConfig, SeccompDeny, TmpfsMount, EGRESS_SOCKET};
pub use profiles::{
    profile_collect, profile_fetch, profile_ingest, profile_materialize, profile_run,
    profile_run_egress, JobContext,
};
pub use seccomp::build_seccomp_filter;
