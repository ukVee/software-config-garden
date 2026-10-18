//! soft-fig install/upgrade helper — the consumer-side machinery from
//! `meta/spec-install.md`. It holds the pieces install and upgrade share:
//!
//! - [`swap`] — the **atomic installed-set swap** (release-pipeline slice 003;
//!   round-2 decision 7, generalized from the original "four" to the
//!   reconciled five-binary set).
//! - [`stage`] — staging the built set + the atomic swap as one routine
//!   (release-pipeline slice 007; shared by install and `softfig upgrade`).
//! - [`detect`] — OS/distro + supervisor detection (slice 005).
//! - [`gate`] — the toolchain gate: distro `rustc` vs the workspace
//!   `rust-version`, with the `rustup` bootstrap fallback (slice 005).
//! - [`prompt`] — the consented, reversible offer model for the integration
//!   steps (systemd unit, MCP registration) (slice 005).
//!
//! The front-door binary (`[[bin]] softfig-install`, `src/main.rs`) composes
//! these. This crate is kept small on purpose: it is built as a static-musl
//! helper binary, so its dependency tree *is* the install trust root
//! (`meta/spec-install.md` → "Download integrity").
//!
//! # The atomic swap
//!
//! [`swap::swap_binaries`] moves a staged set of binaries into the install
//! directory, all-or-nothing to the limit `rename(2)` allows.
//!
//! ## Crash-window analysis
//!
//! `rename(2)` is atomic *per file*; POSIX has no multi-file atomic rename. So
//! the swap cannot make a crash literally leave "old set or new set, never a
//! mix". What it does instead is make the one real intermediate state — a mix —
//! **detectable** and **recoverable**:
//!
//! - **Phase 1 (validate) mutates nothing.** Every member of `set` must exist
//!   at `staged_dir/<name>` and be an executable regular file, or the swap
//!   returns [`SwapError::StagedIncomplete`](swap::SwapError::StagedIncomplete)
//!   *before the first rename*. A half-swap can never start from an incomplete
//!   staged set.
//! - **Phase 2 (swap) renames each `staged_dir/<name>` over `target_dir/<name>`
//!   in `set` order.** A crash mid-phase leaves some names at the new build and
//!   some at the old: a partial install. `softfig_ipc::compat::SetReport::scan`
//!   detects it (`consistent_version()` is `None`), and a re-run of the swap —
//!   with the staged dir re-populated, which is what the install path does when
//!   it re-stages from the build output — converges, because every name is
//!   renamed to the new build regardless of what it held before.
//! - **Ordering.** The set is renamed in `softfig_ipc::compat::INSTALLED_SET`
//!   order — the CLI first, the two daemons (`softfig-keeperd` second,
//!   `softfig-growlightd` last). A crash mid-swap therefore at worst leaves a
//!   *new* client talking to an *old* daemon — exactly the mismatch the version
//!   handshake (slice 002) refuses with a clear message — rather than a new
//!   daemon served by clients that predate its expectations.
//! - **The swap deletes nothing.** An old binary is replaced by `rename`, the
//!   same atomic syscall `install(1)` uses per file.
//!
//! ## Same-filesystem staging
//!
//! `rename(2)` fails with `EXDEV` across filesystems, so `staged_dir` must live
//! on the same filesystem as `target_dir`. The helper stages in a sibling temp
//! dir of the install directory, never `/tmp` on a tmpfs.
//!
//! ## Binary-format-agnostic
//!
//! The swap never reads a binary's contents: it stats for the executable bit
//! and renames. It is agnostic to what the files *are*, so a future
//! busybox-style multiplexer (an explicitly-later decision) or any other shape
//! slots into the same routine unchanged.

#![forbid(unsafe_code)]

pub mod detect;
pub mod gate;
pub mod prompt;
pub mod stage;
pub mod swap;

pub use stage::{stage_and_swap, StageOutcome};
pub use swap::{swap_binaries, Result, SwapError};
