//! Loose object directory.
//!
//! Each object is a ciphertext blob produced by `softfig-vault`'s
//! `encrypt_blob` (master-keyed convergent AEAD). The store hashes the
//! ciphertext with BLAKE3 to produce its address, then writes the bytes
//! to `<objects>/<aa>/<rest>` where `aa` is the first hex byte of the
//! hash and `rest` is the remaining 31. Two-byte fanout keeps any one
//! directory from growing to a million entries.
//!
//! Writes go through a tempfile + rename to be atomic against crashes.
//! Reads verify the hash against the requested address; a mismatch is a
//! corruption error, not a miss.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use crate::error::{Result, StoreError};
use crate::hash::Hash;
use crate::paths::StorePaths;

#[derive(Debug, Clone)]
pub struct ObjectStore {
    paths: StorePaths,
}

impl ObjectStore {
    pub fn new(paths: StorePaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &StorePaths {
        &self.paths
    }

    /// Create the `objects/` root if it doesn't exist yet.
    pub fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(self.paths.objects_dir())?;
        Ok(())
    }

    /// Hash the ciphertext, write it under `objects/<aa>/<rest>`, return the hash.
    /// Idempotent: if the object is already present with the same hash, the
    /// write is skipped. Atomic via tempfile + rename.
    pub fn put(&self, ciphertext: &[u8]) -> Result<Hash> {
        let hash = Hash::of(ciphertext);
        let target = self.paths.object_path(&hash);

        if target.exists() {
            return Ok(hash);
        }

        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp = self.tempfile_for(&target);
        {
            let mut f = File::create(&tmp)?;
            f.write_all(ciphertext)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &target)?;
        Ok(hash)
    }

    /// Read an object by hash. Verifies the on-disk content matches the
    /// requested address; returns `ObjectCorrupt` if not.
    pub fn get(&self, hash: &Hash) -> Result<Vec<u8>> {
        let path = self.paths.object_path(hash);
        if !path.exists() {
            return Err(StoreError::ObjectNotFound(*hash));
        }
        let bytes = fs::read(&path)?;
        let actual = Hash::of(&bytes);
        if actual != *hash {
            return Err(StoreError::ObjectCorrupt {
                expected: *hash,
                actual,
            });
        }
        Ok(bytes)
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.paths.object_path(hash).exists()
    }

    /// Remove a loose object by hash. Used by `softfig-vcs`'s gc to collect
    /// a blob unreachable from every live chain tip. Idempotent: a missing
    /// object is not an error (already gone / never written).
    pub fn remove(&self, hash: &Hash) -> Result<()> {
        let path = self.paths.object_path(hash);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Iterate every object on disk, yielding `(declared_hash, bytes_on_disk)`.
    /// `declared_hash` is parsed from the filename, *not* re-hashed — fsck
    /// uses this to detect mismatches.
    pub fn iter(&self) -> Result<ObjectIter> {
        Ok(ObjectIter::new(self.paths.objects_dir()))
    }

    fn tempfile_for(&self, target: &std::path::Path) -> PathBuf {
        let pid = std::process::id();
        let nonce: u64 = rand_u64();
        let name = format!(
            "{}.tmp.{}.{}",
            target.file_name().and_then(|s| s.to_str()).unwrap_or("obj"),
            pid,
            nonce
        );
        target.with_file_name(name)
    }
}

fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Don't pull a full RNG dep just for a tempfile suffix.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    now ^ (std::process::id() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

/// Walks `objects/<aa>/<rest>` lazily, yielding `(declared_hash, bytes)`.
/// `declared_hash` comes from the filename. fsck compares it to
/// `BLAKE3(bytes)`; consumers that just want content should use
/// `ObjectStore::get` which already verifies.
#[derive(Debug)]
pub struct ObjectIter {
    fanout: Option<fs::ReadDir>,
    current: Option<(String, fs::ReadDir)>,
}

impl ObjectIter {
    fn new(root: PathBuf) -> Self {
        let fanout = fs::read_dir(&root).ok();
        Self {
            fanout,
            current: None,
        }
    }
}

impl Iterator for ObjectIter {
    type Item = Result<(Hash, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((head, iter)) = self.current.as_mut() {
                match iter.next() {
                    Some(Ok(entry)) => {
                        let tail = entry.file_name().to_string_lossy().to_string();
                        let hex = format!("{head}{tail}");
                        let hash = match Hash::from_hex(&hex) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        let bytes = match fs::read(entry.path()) {
                            Ok(b) => b,
                            Err(e) => return Some(Err(e.into())),
                        };
                        return Some(Ok((hash, bytes)));
                    }
                    Some(Err(e)) => return Some(Err(e.into())),
                    None => self.current = None,
                }
            }
            let fanout = self.fanout.as_mut()?;
            match fanout.next()? {
                Ok(entry) => {
                    if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    let head = entry.file_name().to_string_lossy().to_string();
                    if head.len() != 2 || !head.chars().all(|c| c.is_ascii_hexdigit()) {
                        continue;
                    }
                    let inner = match fs::read_dir(entry.path()) {
                        Ok(d) => d,
                        Err(e) => return Some(Err(e.into())),
                    };
                    self.current = Some((head, inner));
                }
                Err(e) => return Some(Err(e.into())),
            }
        }
    }
}
