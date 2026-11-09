//! The `tests/fixtures/migrate/` loader the migration tests share.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use softfig_ipc::queue_v2::migrate::LegacyFiles;

fn load(root: &Path, dir: &Path, into: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            load(root, &path, into);
        } else {
            let key = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
            into.insert(key, fs::read_to_string(&path).unwrap());
        }
    }
}

/// The fixture snapshot: `garden/` keyed garden-relative, `batons/` keyed
/// runtime-relative.
pub fn fixture_files() -> LegacyFiles {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/migrate");
    let mut files = LegacyFiles::default();
    load(&root.join("garden"), &root.join("garden"), &mut files.garden);
    load(&root.join("batons"), &root.join("batons"), &mut files.batons);
    files
}

