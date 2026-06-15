//! The volatile endpoint sidecar — `<state_root>/.softfig/peers-endpoints.toml`.
//!
//! The trust ring ([`crate::ring`]) mixes two very differently-paced kinds of
//! state: **membership** (device id / name / transport key / attestation /
//! `paired_at` — changes only on pair/unpair) and **endpoints** (volatile
//! `host:port` that mDNS refreshes every few seconds). Once the *membership*
//! ring lives inside the garden (`config/peers.toml`, committed by the VCS),
//! folding endpoints into it would fire a commit on **every** mDNS sighting
//! (the `.claude/`-style churn problem). So endpoints are split out here: a
//! plain local sidecar beside the vault, **never committed** and never backed
//! up — an endpoint is meaningless on a restored device anyway, and it is
//! re-learned from mDNS within seconds of unlock.
//!
//! Keyed by the peer's lowercase-hex device id. [`EndpointCache::apply`] merges
//! it back onto a freshly-loaded membership ring at startup; the live browse
//! loop re-captures it from the in-memory ring ([`EndpointCache::capture`]) and
//! rewrites it on each refresh.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::attest::KEY_LEN;
use crate::error::Result;
use crate::ring::Ring;

/// Filename of the endpoint sidecar within `.softfig/`.
pub const ENDPOINT_CACHE_FILE: &str = "peers-endpoints.toml";

/// Path to the endpoint sidecar for a given state root:
/// `<state_root>/.softfig/peers-endpoints.toml`. Sits beside the legacy ring
/// path; volatile, never committed, never backed up.
pub fn endpoint_cache_path(state_root: &Path) -> PathBuf {
    state_root.join(".softfig").join(ENDPOINT_CACHE_FILE)
}

/// Per-device reachable endpoints, persisted out-of-band from membership.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EndpointCache {
    /// `device_id` (lowercase hex) → reachable `host:port` endpoints. A
    /// `BTreeMap` so the on-disk file has a stable key order.
    #[serde(default)]
    endpoints: BTreeMap<String, Vec<String>>,
}

impl EndpointCache {
    /// Load the sidecar. A missing file is an empty cache (the common case —
    /// it is rebuilt from mDNS within seconds of unlock).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    /// Atomically write the sidecar (temp + rename), creating `.softfig/` if
    /// needed. Unlike membership this is never committed, so the temp+rename's
    /// two filesystem events are harmless (the file lives outside the VCS walk).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(self)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Snapshot every ring member's current endpoints. Members with no known
    /// endpoint are omitted (nothing to persist).
    pub fn capture(ring: &Ring) -> Self {
        let endpoints = ring
            .peers()
            .iter()
            .filter(|p| !p.endpoints.is_empty())
            .map(|p| (p.fingerprint(), p.endpoints.clone()))
            .collect();
        Self { endpoints }
    }

    /// Merge the cached endpoints onto a freshly-loaded membership `ring`. A
    /// cache entry for a device no longer in the ring is ignored
    /// ([`Ring::merge_endpoints`] returns `false`); a malformed hex key is
    /// skipped.
    pub fn apply(&self, ring: &mut Ring) {
        for (fp, eps) in &self.endpoints {
            if let Ok(bytes) = hex::decode(fp) {
                if let Ok(device_id) = <[u8; KEY_LEN]>::try_from(bytes.as_slice()) {
                    ring.merge_endpoints(&device_id, eps);
                }
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::static_attestation_message;
    use crate::ring::RingEntry;
    use ed25519_dalek::{Signer, SigningKey};

    /// A verifiable ring entry with the given endpoints.
    fn entry(id_seed: u8, tk_seed: u8, name: &str, endpoints: Vec<String>) -> RingEntry {
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
            endpoints,
            attestation,
            paired_at: 1,
        }
    }

    #[test]
    fn capture_apply_round_trips_endpoints() {
        let mut ring = Ring::default();
        ring.upsert(entry(1, 2, "laptop", vec!["192.168.1.5:9100".into()]));
        ring.upsert(entry(3, 4, "phone", vec![])); // no endpoint → omitted

        let cache = EndpointCache::capture(&ring);
        assert_eq!(cache.endpoints.len(), 1, "only the device with endpoints");

        // A fresh membership-only ring (endpoints stripped) gets them merged
        // back from the cache.
        let mut membership = Ring::default();
        membership.upsert(entry(1, 2, "laptop", vec![]));
        membership.upsert(entry(3, 4, "phone", vec![]));
        cache.apply(&mut membership);

        let laptop = entry(1, 2, "laptop", vec![]).device_id;
        assert_eq!(
            membership.get(&laptop).unwrap().endpoints,
            vec!["192.168.1.5:9100".to_string()]
        );
    }

    #[test]
    fn save_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = endpoint_cache_path(dir.path());

        let mut ring = Ring::default();
        ring.upsert(entry(5, 6, "tablet", vec!["10.0.0.2:9100".into()]));
        let cache = EndpointCache::capture(&ring);
        cache.save(&path).unwrap();

        let loaded = EndpointCache::load(&path).unwrap();
        let mut membership = Ring::default();
        membership.upsert(entry(5, 6, "tablet", vec![]));
        loaded.apply(&mut membership);
        let id = entry(5, 6, "tablet", vec![]).device_id;
        assert_eq!(
            membership.get(&id).unwrap().endpoints,
            vec!["10.0.0.2:9100".to_string()]
        );
    }

    #[test]
    fn missing_file_is_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EndpointCache::load(&endpoint_cache_path(dir.path())).unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn apply_ignores_unknown_and_malformed_keys() {
        let mut cache = EndpointCache::default();
        // A device not in the ring + a malformed hex key — both skipped, no panic.
        cache
            .endpoints
            .insert("ff".repeat(32), vec!["1.2.3.4:9100".into()]);
        cache
            .endpoints
            .insert("not-hex".into(), vec!["5.6.7.8:9100".into()]);
        let mut ring = Ring::default();
        ring.upsert(entry(9, 10, "known", vec![]));
        cache.apply(&mut ring); // no-op for both entries
        let id = entry(9, 10, "known", vec![]).device_id;
        assert!(ring.get(&id).unwrap().endpoints.is_empty());
    }
}
