//! The runner's stored certificate (spec §3.1): the device identity's signed
//! certificate, plus its signature, held at `cert.toml`.
//!
//! runnerd stores the certificate as the *hex-string wire form* (the exact
//! serde shape `softfig-net::runner_cert::RunnerCert` serializes to, shared here
//! as a plain struct) plus the identity's signature. This on-disk form keeps the
//! storage self-contained; the wire module (`wire.rs`) converts it to the
//! protobuf `RunnerHandshake` payload for the Noise handshake (slice 003). The
//! fields are otherwise opaque to runnerd — it reports `serial`/`expires_at`
//! (status), hands the record to a requester's handshake, and revokes it.
//!
//! This struct's field set MUST stay byte-compatible with
//! `softfig-ipc::verbs::RunnerCertWire` + a `signature` field.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// The signed runner certificate as stored in `cert.toml`. Keys and serial are
/// lowercase hex; the signature is the device identity's Ed25519 signature over
/// the canonical bytes, also lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCert {
    pub device_id: String,
    pub runner_transport_pubkey: String,
    pub runner_attest_pubkey: String,
    pub serial: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub signature: String,
}

impl StoredCert {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// A signed revocation record (spec §3.1), held locally until slice 003's
/// `RunnerCertRevoke` wire frame distributes it to the ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRevocation {
    pub device_id: String,
    pub serial: String,
    pub signature: String,
}

impl StoredRevocation {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_cert_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert.toml");
        let c = StoredCert {
            device_id: "aa".repeat(32),
            runner_transport_pubkey: "bb".repeat(32),
            runner_attest_pubkey: "cc".repeat(32),
            serial: "dd".repeat(16),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_000 + 90 * 24 * 60 * 60,
            signature: "ee".repeat(64),
        };
        c.save(&path).unwrap();
        assert_eq!(StoredCert::load(&path).unwrap(), c);
    }

    #[test]
    fn stored_revocation_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revocation.toml");
        let r = StoredRevocation {
            device_id: "aa".repeat(32),
            serial: "dd".repeat(16),
            signature: "ee".repeat(64),
        };
        r.save(&path).unwrap();
        assert_eq!(StoredRevocation::load(&path).unwrap(), r);
    }
}
