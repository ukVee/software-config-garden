//! `softfig-sandbox-collect` — BLAKE3 the declared artifact globs inside the
//! collect sandbox (spec remote-runner §6 step 6, §8, slice 006).
//!
//! Runs as the command inside the `profile_collect` sandbox, with its working
//! directory `/src` (the materialized tree). It matches the caller-supplied
//! glob patterns against the files under the current directory and prints one
//! JSON object per match — `{"path":…,"size":…,"blake3":…}`, one per line — so
//! the executor can turn them into the attestation's `artifacts` table.
//!
//! The tree's author picks every filename, so a row is JSON rather than bare
//! tab-separated fields: a `\n` or `\t` in a name is escaped inside its own
//! row and can't forge another (pre-merge review m3). A name that isn't UTF-8
//! can't be attested faithfully, so it is skipped with a note on stderr.
//!
//! Each file is hashed as a stream, never read whole, so one large artifact
//! can't exhaust the unit's memory; `size` is the byte count actually hashed.
//!
//! It reads only **regular files inside the sandbox view**: `walkdir` does not
//! follow symlinks (files or dirs), so a symlink in the tree resolves (if at
//! all) inside the restricted view and is never followed to a host file. This
//! is the "symlinks can't leak host files" property from the slice-006
//! done-when list.

use std::io::Write;
use std::path::Path;

use globset::{Glob, GlobSet};
use serde::Serialize;

/// One output row; the executor's `Artifact` reads the same three fields.
#[derive(Serialize)]
struct Row<'a> {
    path: &'a str,
    size: u64,
    blake3: &'a str,
}

fn main() {
    let globs: Vec<String> = std::env::args().skip(1).collect();
    if globs.is_empty() {
        return;
    }
    let parsed: Vec<Glob> = match globs.iter().map(|g| Glob::new(g.as_str())).collect() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("softfig-sandbox-collect: bad glob: {e}");
            std::process::exit(2);
        }
    };
    let set = GlobSet::new(&parsed).expect("pre-parsed globs are valid");

    let cwd = std::env::current_dir().unwrap_or_else(|_| Path::new("/").to_path_buf());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for entry in walkdir::WalkDir::new(&cwd).into_iter().filter_map(|e| e.ok()) {
        // `DirEntry::file_type()` reports the entry's own type without following
        // symlinks, so a symlink (file or dir) is skipped, never followed.
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = match entry.path().strip_prefix(&cwd) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if !set.is_match(rel) {
            continue;
        }
        let Some(path) = rel.to_str() else {
            eprintln!("softfig-sandbox-collect: skipping a non-UTF-8 name: {}", rel.display());
            continue;
        };
        // Unreadable inside the view: skip, don't fail the job.
        let Ok((size, hash)) = hash_file(entry.path()) else {
            continue;
        };
        let hex = hash.to_hex();
        let row = Row { path, size, blake3: hex.as_str() };
        let mut line = serde_json::to_vec(&row).expect("a row of str + u64 always serializes");
        line.push(b'\n');
        let _ = out.write_all(&line);
    }
}

/// Stream `path` through BLAKE3, returning the byte count hashed and the hash.
fn hash_file(path: &Path) -> std::io::Result<(u64, blake3::Hash)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let size = std::io::copy(&mut file, &mut hasher)?;
    Ok((size, hasher.finalize()))
}
