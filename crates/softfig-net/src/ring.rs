//! The network trust ring — `<state_root>/.softfig/peers.toml`.
//!
//! "I recognise this device and hold its keys." A [`RingEntry`] is written for
//! a peer the moment SAS-confirmed pairing succeeds (see [`crate::pairing`]),
//! and read back to authenticate `IK` reconnects, relay registrations
//! (M5a-3), and — later — commit signatures (M5b+).
//!
//! This is **one of three distinct trust layers** and must not be conflated
//! with the others:
//!
//! * **network ring** (here) — pairing: who I can talk to securely.
//! * **unlock ACL** (`trust.toml`, vault) — who may unlock me. Untouched here.
//! * **shared-subtree membership** (M5d) — who may read/write a shared chain.
//!
//! Pairing joins the network ring and grants *nothing else*.
//!
//! Each row carries the peer's Ed25519 self-attestation over its X25519
//! transport static (see [`crate::attest`]). [`Ring::load`] re-verifies every
//! attestation, so a hand-edited or tampered `peers.toml` (a swapped key, a
//! forged row) is rejected on load rather than silently trusted. Keys are
//! stored as lowercase hex; the file is written atomically (temp + rename).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::attest::{verify_static_attestation, KEY_LEN, SIG_LEN};
use crate::error::{NetError, Result};

/// Filename of the ring within `.softfig/`.
pub const RING_FILE: &str = "peers.toml";
/// On-disk schema version for `peers.toml`.
pub const RING_VERSION: u32 = 1;

/// Path to the ring for a given state root: `<state_root>/.softfig/peers.toml`.
/// Distinct from the vault's `.softfig/vault/` subtree — the ring lives beside
/// it, not inside it, since it is device-network state, not vault key material.
pub fn ring_path(state_root: &Path) -> PathBuf {
    state_root.join(".softfig").join(RING_FILE)
}

/// One paired device. The `attestation` binds `device_id` (Ed25519 identity) to
/// `transport_pubkey` (X25519 Noise static); [`RingEntry::verify`] checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingEntry {
    /// The peer's Ed25519 identity public key — its stable device id.
    pub device_id: [u8; KEY_LEN],
    /// Human-readable device name (advertised in the handshake; not trusted for
    /// anything security-sensitive).
    pub name: String,
    /// The peer's X25519 transport static, used to key `IK` reconnects.
    pub transport_pubkey: [u8; KEY_LEN],
    /// Reachable endpoints (`host:port`). Empty at pairing time; populated and
    /// refreshed by mDNS / relay discovery in M5a-3.
    pub endpoints: Vec<String>,
    /// The peer's Ed25519 signature over its own X25519 static (field 4 of the
    /// handshake `HelloPayload`).
    pub attestation: [u8; SIG_LEN],
    /// When the pairing happened, Unix seconds.
    pub paired_at: i64,
}

impl RingEntry {
    /// Verify this row's attestation binds its `device_id` to its
    /// `transport_pubkey`. Called for every row on [`Ring::load`].
    pub fn verify(&self) -> bool {
        verify_static_attestation(&self.device_id, &self.transport_pubkey, &self.attestation)
    }

    /// Lowercase hex of the device id — the stable fingerprint used for display
    /// and (M5a-4) the `softfig pair <fingerprint>` / `softfig unpair` CLI.
    pub fn fingerprint(&self) -> String {
        hex::encode(self.device_id)
    }
}

/// The in-memory ring. Keyed by `device_id`; entries are unique per device.
#[derive(Clone, Debug, Default)]
pub struct Ring {
    peers: Vec<RingEntry>,
}

impl Ring {
    /// Load and **verify** the ring. A missing file is an empty ring (a fresh,
    /// never-paired device). Any row whose attestation fails to verify rejects
    /// the whole load — a tampered ring is a tamper signal, not noise to skip.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::from_toml_str(&fs::read_to_string(path)?)
    }

    /// Parse and **verify** a ring from already-read `peers.toml` TOML text.
    /// Same verification as [`Ring::load`] — any row whose attestation fails to
    /// verify rejects the whole parse (a tampered membership file is a tamper
    /// signal, not noise to skip). For callers that read the membership file
    /// through their own mount-safe path (keeperd's `WorkTree`) rather than a
    /// direct `fs::read`.
    pub fn from_toml_str(raw: &str) -> Result<Self> {
        let doc: RingDoc = toml::from_str(raw)?;
        let mut peers = Vec::with_capacity(doc.peer.len());
        for row in doc.peer {
            let entry = row.into_entry()?;
            if !entry.verify() {
                return Err(NetError::Protocol(
                    "ring entry attestation does not verify (tampered peers.toml?)",
                ));
            }
            peers.push(entry);
        }
        Ok(Self { peers })
    }

    /// Serialize **membership only** (endpoints stripped) to a TOML string —
    /// the form persisted to the in-garden `config/peers.toml`. Endpoints are
    /// volatile mDNS state that would dirty the garden on every sighting; they
    /// live in the [`crate::endpoint_cache`] sidecar instead. Unlike
    /// [`Ring::save`], this hands the bytes back so the caller can write them
    /// through its own self-write-suppressed path (one write event the watcher
    /// can drop), rather than a temp+rename (two events `mark_self_write` can't
    /// both catch).
    pub fn to_membership_toml(&self) -> Result<String> {
        let doc = RingDoc {
            version: RING_VERSION,
            peer: self
                .peers
                .iter()
                .map(|e| {
                    let mut row = PeerRow::from_entry(e);
                    row.endpoints.clear();
                    row
                })
                .collect(),
        };
        Ok(toml::to_string_pretty(&doc)?)
    }

    /// Atomically write the ring (temp file + rename), creating `.softfig/` if
    /// needed.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let doc = RingDoc {
            version: RING_VERSION,
            peer: self.peers.iter().map(PeerRow::from_entry).collect(),
        };
        let raw = toml::to_string_pretty(&doc)?;

        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// All paired devices.
    pub fn peers(&self) -> &[RingEntry] {
        &self.peers
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Look up a peer by device id.
    pub fn get(&self, device_id: &[u8; KEY_LEN]) -> Option<&RingEntry> {
        self.peers.iter().find(|e| &e.device_id == device_id)
    }

    /// Add `entry`, or replace an existing row with the same `device_id`
    /// (re-pairing refreshes name / transport key / endpoints). Idempotent.
    pub fn upsert(&mut self, entry: RingEntry) {
        match self.peers.iter_mut().find(|e| e.device_id == entry.device_id) {
            Some(slot) => *slot = entry,
            None => self.peers.push(entry),
        }
    }

    /// Remove a peer by device id (unpair). Returns whether a row was removed.
    pub fn remove(&mut self, device_id: &[u8; KEY_LEN]) -> bool {
        let before = self.peers.len();
        self.peers.retain(|e| &e.device_id != device_id);
        self.peers.len() != before
    }

    /// Merge freshly-discovered `endpoints` into the row for `device_id`,
    /// de-duplicating and preserving order. Returns whether a matching ring
    /// member existed (a discovery for a non-member is ignored). Used by M5a-3
    /// discovery to refresh a peer's reachable endpoints from mDNS / the relay;
    /// merging rather than replacing keeps a known-good endpoint if a single
    /// browse happens to miss it. Persist with [`Ring::save`] to keep it.
    pub fn merge_endpoints(&mut self, device_id: &[u8; KEY_LEN], endpoints: &[String]) -> bool {
        match self.peers.iter_mut().find(|e| &e.device_id == device_id) {
            Some(entry) => {
                for ep in endpoints {
                    if !entry.endpoints.contains(ep) {
                        entry.endpoints.push(ep.clone());
                    }
                }
                true
            }
            None => false,
        }
    }
}

// --- TOML representation ----------------------------------------------------
//
// Strongly-typed `RingEntry` <-> hex-string `PeerRow`. Doing the conversion by
// hand (rather than a serde-with shim on `[u8; N]`) keeps length validation and
// the hex contract explicit, and gives a clear error site for a malformed file.

#[derive(Serialize, Deserialize)]
struct RingDoc {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    peer: Vec<PeerRow>,
}

fn default_version() -> u32 {
    RING_VERSION
}

#[derive(Serialize, Deserialize)]
struct PeerRow {
    device_id: String,
    name: String,
    transport_pubkey: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    attestation: String,
    paired_at: i64,
}

impl PeerRow {
    fn from_entry(e: &RingEntry) -> Self {
        Self {
            device_id: hex::encode(e.device_id),
            name: e.name.clone(),
            transport_pubkey: hex::encode(e.transport_pubkey),
            endpoints: e.endpoints.clone(),
            attestation: hex::encode(e.attestation),
            paired_at: e.paired_at,
        }
    }

    fn into_entry(self) -> Result<RingEntry> {
        Ok(RingEntry {
            device_id: hex_array::<KEY_LEN>(&self.device_id, "device_id")?,
            name: self.name,
            transport_pubkey: hex_array::<KEY_LEN>(&self.transport_pubkey, "transport_pubkey")?,
            endpoints: self.endpoints,
            attestation: hex_array::<SIG_LEN>(&self.attestation, "attestation")?,
            paired_at: self.paired_at,
        })
    }
}

/// Decode a lowercase-hex string into a fixed-size byte array, mapping any
/// malformed hex or wrong length to a protocol error naming the field.
fn hex_array<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).map_err(|_| {
        NetError::Protocol(match field {
            "device_id" => "ring device_id is not valid hex",
            "transport_pubkey" => "ring transport_pubkey is not valid hex",
            _ => "ring attestation is not valid hex",
        })
    })?;
    bytes.try_into().map_err(|_| {
        NetError::Protocol(match field {
            "device_id" => "ring device_id wrong length",
            "transport_pubkey" => "ring transport_pubkey wrong length",
            _ => "ring attestation wrong length",
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::static_attestation_message;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a self-consistent (verifiable) ring entry for a test device.
    fn entry(id_seed: u8, tk_seed: u8, name: &str) -> RingEntry {
        let id = SigningKey::from_bytes(&[id_seed; 32]);
        let transport_pubkey =
            x25519_dalek::x25519([tk_seed; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let attestation = id
            .sign(&static_attestation_message(&transport_pubkey))
            .to_bytes();
        RingEntry {
            device_id: id.verifying_key().to_bytes(),
            name: name.into(),
            transport_pubkey,
            endpoints: vec!["192.168.1.20:9100".into()],
            attestation,
            paired_at: 1_700_000_000,
        }
    }

    #[test]
    fn round_trips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = ring_path(dir.path());

        let mut ring = Ring::default();
        ring.upsert(entry(1, 2, "laptop"));
        ring.upsert(entry(3, 4, "phone"));
        ring.save(&path).unwrap();

        let loaded = Ring::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.peers(), ring.peers());
    }

    #[test]
    fn membership_toml_strips_endpoints() {
        let mut ring = Ring::default();
        ring.upsert(entry(1, 2, "laptop")); // entry() seeds an endpoint
        let toml = ring.to_membership_toml().unwrap();
        assert!(
            !toml.contains("endpoints"),
            "membership form must omit endpoints, got:\n{toml}"
        );
        assert!(toml.contains("name = \"laptop\""));
        // It round-trips back to a verifiable, endpoint-free membership ring.
        let dir = tempfile::tempdir().unwrap();
        let path = ring_path(dir.path());
        fs::write(path_with_dirs(&path), &toml).unwrap();
        let loaded = Ring::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.peers()[0].endpoints.is_empty());
        assert!(loaded.peers()[0].verify());
    }

    /// Create the parent dir for `path` and return it (membership writes don't
    /// go through `Ring::save`, so this test does the mkdir itself).
    fn path_with_dirs(path: &Path) -> &Path {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        path
    }

    #[test]
    fn missing_file_is_empty_ring() {
        let dir = tempfile::tempdir().unwrap();
        let ring = Ring::load(&ring_path(dir.path())).unwrap();
        assert!(ring.is_empty());
    }

    #[test]
    fn upsert_replaces_same_device() {
        let mut ring = Ring::default();
        ring.upsert(entry(5, 6, "old-name"));
        // Same identity key, new transport key + name → one row, replaced.
        let mut updated = entry(5, 7, "new-name");
        updated.endpoints = vec![];
        let id = updated.device_id;
        ring.upsert(updated);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.get(&id).unwrap().name, "new-name");
    }

    #[test]
    fn remove_unpairs() {
        let mut ring = Ring::default();
        let e = entry(8, 9, "gone");
        let id = e.device_id;
        ring.upsert(e);
        assert!(ring.remove(&id));
        assert!(!ring.remove(&id)); // second remove is a no-op
        assert!(ring.is_empty());
    }

    #[test]
    fn load_rejects_tampered_attestation() {
        let dir = tempfile::tempdir().unwrap();
        let path = ring_path(dir.path());

        // Persist a valid entry, then flip a byte of its transport key so the
        // stored attestation no longer binds it.
        let mut ring = Ring::default();
        ring.upsert(entry(10, 11, "victim"));
        ring.save(&path).unwrap();

        let mut text = fs::read_to_string(&path).unwrap();
        let good = hex::encode(
            x25519_dalek::x25519([11u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES),
        );
        let mut bad_bytes = x25519_dalek::x25519([11u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        bad_bytes[0] ^= 0x01;
        text = text.replace(&good, &hex::encode(bad_bytes));
        fs::write(&path, text).unwrap();

        match Ring::load(&path) {
            Err(NetError::Protocol(_)) => {}
            other => panic!("expected tampered ring rejection, got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_malformed_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = ring_path(dir.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "version = 1\n\n[[peer]]\ndevice_id = \"zz\"\nname = \"x\"\n\
             transport_pubkey = \"00\"\nattestation = \"00\"\npaired_at = 1\n",
        )
        .unwrap();
        assert!(matches!(Ring::load(&path), Err(NetError::Protocol(_))));
    }
}
