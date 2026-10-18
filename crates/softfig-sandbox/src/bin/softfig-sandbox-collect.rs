//! `softfig-sandbox-collect` — BLAKE3 the declared artifact globs inside the
//! collect sandbox (spec remote-runner §6 step 6, §8, slice 006).
//!
//! Runs as the command inside the `profile_collect` sandbox, with its working
//! directory `/src` (the materialized tree). It matches the caller-supplied
//! glob patterns against the files under the current directory and prints one
//! line per match — `<blake3hex>\t<size>\t<relpath>` — so the executor can turn
//! them into the attestation's `artifacts` table.
//!
//! It reads only **regular files inside the sandbox view**: `walkdir` does not
//! follow symlinks (files or dirs), so a symlink in the tree resolves (if at
//! all) inside the restricted view and is never followed to a host file. This
//! is the "symlinks can't leak host files" property from the slice-006
//! done-when list.

use std::path::Path;

use globset::{Glob, GlobSet};

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
        // Unreadable inside the view: skip, don't fail the job.
        if let Ok(bytes) = std::fs::read(entry.path()) {
            let hash = blake3::hash(&bytes);
            let _ = std::io::Write::write_all(
                &mut out,
                format!("{}\t{}\t{}\n", hash.to_hex(), bytes.len(), rel.display())
                    .as_bytes(),
            );
        }
    }
}
