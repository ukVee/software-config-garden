//! How the deploy engine reads each dot's **source** — the one seam that lets a
//! FUSE-mode daemon deploy safely.
//!
//! ## Why a seam (the mount-I/O-under-`inner` hazard)
//!
//! `config/deploy.toml` + `config/source/` live under the garden root, which in
//! FUSE mode *is* the mount the keeper daemon serves. A `std::fs::read` of that
//! path from **inside** the daemon, while it holds `daemon.inner`, is a
//! self-read of its own mount — the documented 2026-06-21 deadlock class the
//! WorkTree / `workdir_snapshot` machinery exists to prevent. Worse, even absent
//! deadlock the kernel hands back the **reader-redacted projection**, so a
//! Layer-B-sealed source would deploy `[sealed:…]` placeholder bytes into a live
//! target (a sealed-content leak into real dotfiles).
//!
//! [`plan`](crate::plan) therefore reads every dot's source *only* through a
//! [`SourceReader`], never `std::fs` directly, and captures the bytes into the
//! plan so [`apply`](crate::apply) re-materializes exactly what was planned
//! without touching the source a second time. Two implementations:
//!
//! * [`FsSource`] — the byte-for-byte `std::fs` reader. Correct for the
//!   `softfig deploy` CLI (a *separate process* from the daemon; reading the
//!   FUSE plaintext from outside never self-reads a mount) and for non-FUSE
//!   (M1c-compat / direct) daemons.
//! * [`MemSource`] — an in-memory reader. The FUSE-mode daemon snapshots each
//!   dot's **plaintext** from its mount-safe working-tree view (tip ∪ overlay,
//!   no kernel round-trip, no redaction) into this *before* dropping `inner`,
//!   then runs the blocking plan/apply lock-free. It is also the test seam that
//!   stands in for FUSE mode, where the workspace suite has no `/dev/fuse`.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::{DeployPaths, Result};

/// A dot's source as the planner sees it: file bytes, a directory (M4a rejects
/// directory sources), or absent.
#[derive(Debug, Clone)]
pub enum SourceEntry {
    File(Vec<u8>),
    Directory,
    Missing,
}

/// Reads a dot's source, given its `source` string (relative to
/// `config/source/`). The engine's only door to source content — see the module
/// docs for why that indirection exists.
pub trait SourceReader {
    /// Classify + read the source at `source_rel`.
    fn read_source(&self, source_rel: &str) -> Result<SourceEntry>;
}

/// The default `std::fs` source reader: `config/source/<source_rel>` read
/// straight off disk.
pub struct FsSource {
    source_dir: PathBuf,
}

impl FsSource {
    /// Read sources from `paths`' `config/source/` directory.
    pub fn new(paths: &DeployPaths) -> Self {
        Self {
            source_dir: paths.source_dir(),
        }
    }
}

impl SourceReader for FsSource {
    fn read_source(&self, source_rel: &str) -> Result<SourceEntry> {
        let abs = self.source_dir.join(source_rel);
        match std::fs::symlink_metadata(&abs) {
            Ok(md) if md.file_type().is_dir() => Ok(SourceEntry::Directory),
            Ok(_) => Ok(SourceEntry::File(std::fs::read(&abs)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SourceEntry::Missing),
            Err(e) => Err(e.into()),
        }
    }
}

/// An in-memory source reader keyed by the dot's `source` string. Anything not
/// inserted reads back as [`SourceEntry::Missing`], so a config referencing an
/// absent source still surfaces the normal `SourceNotFound` error.
#[derive(Debug, Default)]
pub struct MemSource {
    entries: HashMap<String, SourceEntry>,
}

impl MemSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `source_rel` as a regular file with `bytes` (the plaintext the
    /// daemon's working-tree read yielded).
    pub fn insert_file(&mut self, source_rel: impl Into<String>, bytes: Vec<u8>) {
        self.entries
            .insert(source_rel.into(), SourceEntry::File(bytes));
    }

    /// Record `source_rel` as a directory (so the planner raises the M4a
    /// directory-source rejection just as an on-disk directory would).
    pub fn insert_directory(&mut self, source_rel: impl Into<String>) {
        self.entries
            .insert(source_rel.into(), SourceEntry::Directory);
    }
}

impl SourceReader for MemSource {
    fn read_source(&self, source_rel: &str) -> Result<SourceEntry> {
        Ok(self
            .entries
            .get(source_rel)
            .cloned()
            .unwrap_or(SourceEntry::Missing))
    }
}
