//! soft-fig rescue: the recovery-wedge artifact (`meta/spec-packs.md` →
//! "Recovery packs" → phase 1; `meta/spec-release.md` → Artifacts #3). A
//! single prebuilt binary that runs from a live USB or chroot with no install,
//! no daemon, no FUSE, no vault unlock, and no network requirement.
//!
//! This crate is two things, kept apart on purpose:
//!
//! - [`carry`] — the **carry-file format**: phase 1's one portable output, a
//!   self-contained plaintext document that states in-file it is unencrypted
//!   and stamps [`carry::CARRY_FORMAT_VERSION`]. `softfig onboard` (phase 2,
//!   `recovery-pack-v1`) grows it into a garden, so the version it carries is
//!   the phase-1↔phase-2 compatibility surface.
//! - [`packs`] — the **packs seam**: where recovery packs would be looked up.
//!   Declared, not embedded — embedding the signed default set lands with
//!   `recovery-pack-v1`.
//!
//! The `[[bin]] softfig-rescue` (`src/main.rs`) composes them. The crate links
//! no FUSE, no async runtime, and no daemon crates: its dependency tree *is*
//! the rescue trust root, and `ldd` on the built binary must show no
//! `libfuse3`.

#![forbid(unsafe_code)]

pub mod carry;
pub mod packs;
