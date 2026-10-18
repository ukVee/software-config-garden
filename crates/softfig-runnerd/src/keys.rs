//! The runner's two long-lived keys (spec §3.1).
//!
//! `softfig-runnerd` generates its own **X25519 transport static** (Noise key
//! agreement, one connection per job) and **Ed25519 attest key** (signs job
//! attestations, §8). They are *not* vault-sealed — the runner must keep
//! serving while the laptop garden is locked — and are instead protected at
//! rest by the laptop's disk encryption and by file modes (`keys/` 0700, each
//! key 0600). Neither key can read a garden or sign commits; they only accept
//! jobs and sign attestations.
//!
//! The transport secret is held as raw bytes in a [`zeroize::Zeroizing`] guard
//! (the same shape as `softfig-vault`'s transport key); the Ed25519 `SigningKey`
//! zeroizes its scalar on drop. A dropped [`RunnerKeys`] leaves no secret
//! behind.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Filename of the X25519 transport secret under `keys/`.
pub const TRANSPORT_KEY_FILE: &str = "transport.key";
/// Filename of the Ed25519 attest secret under `keys/`.
pub const ATTEST_KEY_FILE: &str = "attest.key";
/// Exact length of a stored secret key in bytes.
const SECRET_LEN: usize = 32;

/// The runner's transport + attest keypair. The X25519 static proves the
/// runner's identity to a requester's Noise handshake; the Ed25519 attest key
/// signs job attestations. The device identity then signs a runner certificate
/// (`softfig-net::runner_cert`) binding both to the device.
pub struct RunnerKeys {
    transport: Zeroizing<[u8; SECRET_LEN]>,
    attest: SigningKey,
}

impl RunnerKeys {
    /// Generate a fresh transport static and attest key from the OS RNG.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let mut transport = [0u8; SECRET_LEN];
        csprng.fill_bytes(&mut transport);
        Self {
            transport: Zeroizing::new(transport),
            attest: SigningKey::generate(&mut csprng),
        }
    }

    /// This runner's X25519 transport public key (the Noise static pubkey).
    pub fn transport_pubkey(&self) -> [u8; 32] {
        x25519_dalek::x25519(*self.transport, x25519_dalek::X25519_BASEPOINT_BYTES)
    }

    /// This runner's Ed25519 attest public key.
    pub fn attest_pubkey(&self) -> [u8; 32] {
        self.attest.verifying_key().to_bytes()
    }

    /// The raw 32-byte transport static, for establishing Noise sessions
    /// (slice 003). Clamping is performed by the DH consumer.
    pub fn transport_secret(&self) -> &[u8; 32] {
        &self.transport
    }

    /// The attest signing key, for signing job attestations (slice 006).
    pub fn attest_signing(&self) -> &SigningKey {
        &self.attest
    }

    /// Write both secrets under `keys_dir` (mode 0600, dir 0700). Idempotent:
    /// overwrites any existing keys, so `softfig runner enable` re-runs cleanly.
    /// Crash-atomic: each file is staged to a temp name and renamed.
    pub fn persist(&self, keys_dir: &Path) -> Result<()> {
        create_keys_dir(keys_dir)?;
        atomic_write_mode(&keys_dir.join(TRANSPORT_KEY_FILE), &self.transport[..])?;
        atomic_write_mode(&keys_dir.join(ATTEST_KEY_FILE), &self.attest.to_bytes())?;
        Ok(())
    }

    /// Load both secrets from `keys_dir`, validating their exact length so a
    /// truncated or tampered file is a hard error rather than a silently-broken
    /// key. Fails if either file is missing.
    pub fn load(keys_dir: &Path) -> Result<Self> {
        let transport = read_secret(&keys_dir.join(TRANSPORT_KEY_FILE), "transport key")?;
        let attest = read_secret(&keys_dir.join(ATTEST_KEY_FILE), "attest key")?;
        Ok(Self {
            transport: Zeroizing::new(transport),
            attest: SigningKey::from_bytes(&attest),
        })
    }
}

fn create_keys_dir(keys_dir: &Path) -> Result<()> {
    fs::create_dir_all(keys_dir)?;
    fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Read a stored secret and validate its exact length. Returned in a
/// [`Zeroizing`] wrapper so the plaintext copy from `fs::read` is scrubbed.
fn read_secret(path: &Path, what: &'static str) -> Result<[u8; SECRET_LEN]> {
    let bytes = Zeroizing::new(fs::read(path)?);
    if bytes.len() != SECRET_LEN {
        return Err(Error::malformed(
            what,
            format!("expected {SECRET_LEN} bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; SECRET_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Stage `bytes` to a temp file next to `path`, then rename into place. The
/// rename is atomic on the same filesystem; the directory entry either points
/// at the old file or the complete new one, never a torn write.
fn atomic_write_mode(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("key"),
        std::process::id()
    ));
    fs::write(&tmp, bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_persist_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let keys = RunnerKeys::generate();
        keys.persist(dir.path()).unwrap();

        let loaded = RunnerKeys::load(dir.path()).unwrap();
        assert_eq!(loaded.transport_pubkey(), keys.transport_pubkey());
        assert_eq!(loaded.attest_pubkey(), keys.attest_pubkey());
    }

    #[test]
    fn distinct_keys_per_generation() {
        let a = RunnerKeys::generate();
        let b = RunnerKeys::generate();
        assert_ne!(a.transport_pubkey(), b.transport_pubkey());
        assert_ne!(a.attest_pubkey(), b.attest_pubkey());
        // And the two keys of one runner are different key material.
        assert_ne!(a.transport_pubkey(), a.attest_pubkey());
    }

    #[test]
    fn key_files_are_0600_and_dir_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        RunnerKeys::generate().persist(dir.path()).unwrap();

        let dir_mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "keys dir must be 0700");

        for f in [TRANSPORT_KEY_FILE, ATTEST_KEY_FILE] {
            let mode = fs::metadata(dir.path().join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f} must be 0600");
        }
    }

    #[test]
    fn truncated_key_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        RunnerKeys::generate().persist(dir.path()).unwrap();
        // Truncate the transport key to 16 bytes.
        fs::write(dir.path().join(TRANSPORT_KEY_FILE), [0u8; 16]).unwrap();
        assert!(matches!(
            RunnerKeys::load(dir.path()),
            Err(Error::Malformed { .. })
        ));
    }

    #[test]
    fn missing_key_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(RunnerKeys::load(dir.path()).is_err());
    }

    #[test]
    fn persist_overwrites_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let keys = RunnerKeys::generate();
        keys.persist(dir.path()).unwrap();
        keys.persist(dir.path()).unwrap(); // second run is a semantic no-op
        let loaded = RunnerKeys::load(dir.path()).unwrap();
        assert_eq!(loaded.transport_pubkey(), keys.transport_pubkey());
        assert_eq!(loaded.attest_pubkey(), keys.attest_pubkey());
    }
}
