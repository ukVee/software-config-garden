//! The packs seam (`meta/spec-packs.md` → "Recovery packs" → phase 1: "The
//! pack ships inside the rescue artifact"). Declared, not embedded: embedding
//! the signed default set lands with `recovery-pack-v1`. What exists today is
//! the lookup contract — where the rescue binary would find packs on the
//! rescue media — so the pack runtime has a stable path to target.

use std::path::{Path, PathBuf};

/// The conventional directory a rescue media keeps its packs in.
pub const PACKS_DIR: &str = "packs";

/// The note printed when the packs seam is exercised: packs are looked up on
/// disk, not yet embedded in the binary. Embedding the signed default set is
/// `recovery-pack-v1`'s seam, not this one's.
pub const PACKS_EMBED_NOTE: &str = "packs are looked up on disk (packs/), not yet \
     embedded in the binary — embedding the signed default set lands with \
     `recovery-pack-v1`";

/// Resolve where the rescue binary looks for packs: the explicit `--packs`
/// override if given, else `exe_dir/[`PACKS_DIR`]` (a `bin/` + `packs/`
/// side-by-side rescue-USB layout). A compiled-in default set is
/// `recovery-pack-v1`'s, not this seam's.
pub fn packs_root(explicit: Option<&Path>, exe_dir: &Path) -> PathBuf {
    match explicit {
        Some(p) => p.to_path_buf(),
        None => exe_dir.join(PACKS_DIR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn an_explicit_packs_dir_wins() {
        let exe = Path::new("/media/rescue/bin");
        let root = packs_root(Some(Path::new("/mnt/packs")), exe);
        assert_eq!(root, Path::new("/mnt/packs"));
    }

    #[test]
    fn the_default_is_packs_beside_the_binary() {
        let exe = Path::new("/media/rescue/bin");
        let root = packs_root(None, exe);
        assert_eq!(root, Path::new("/media/rescue/bin/packs"));
    }
}
