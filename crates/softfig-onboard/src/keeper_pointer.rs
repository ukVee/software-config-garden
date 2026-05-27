//! Write the `keeper.toml` state-root pointer that the daemon reads on
//! `softfig daemon start` to discover a born-in-FUSE garden's relocated
//! `.softfig/` state.
//!
//! The schema mirrors `softfig-keeperd::keeper_toml::KeeperToml` (a
//! top-level `state_root` field). We write it directly rather than
//! depending on `softfig-keeperd` (which would invert the dependency
//! graph — the daemon is a consumer of the engine, not the other way
//! round). The file is a pointer only: no secrets, just a path.
//!
//! Written to two places, matching what `softfig migrate` produces:
//! 1. `<garden_root>/.softfig/keeper.toml` — where `KeeperConfig::discover`
//!    looks. Hidden under the FUSE mount while the daemon runs; visible
//!    again on unmount.
//! 2. `<state_root>/.softfig/keeper.toml` — alongside the relocated state.

use std::path::Path;

use serde::Serialize;

use crate::Result;

#[derive(Serialize)]
struct KeeperPointer<'a> {
    state_root: &'a Path,
}

pub fn write(garden_root: &Path, state_root: &Path) -> Result<()> {
    let pointer = KeeperPointer { state_root };
    let body = toml::to_string_pretty(&pointer)
        .expect("KeeperPointer always serializes to TOML");

    for base in [garden_root, state_root] {
        let dir = base.join(".softfig");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("keeper.toml"), &body)?;
    }
    Ok(())
}
