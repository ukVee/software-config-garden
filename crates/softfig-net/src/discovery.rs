//! LAN discovery over mDNS / DNS-SD (`mdns-sd`).
//!
//! Each unlocked keeper announces the service type `_softfig._tcp.local.` with a
//! TXT record that carries its **device-id fingerprint** (hex of the Ed25519
//! identity = [`RingEntry::fingerprint`](crate::ring::RingEntry::fingerprint))
//! and a paired/unpaired flag. Browsing resolves peers on the same LAN to
//! `host:port` endpoints, which are folded into the matching ring row's
//! `endpoints` (left empty by pairing, see
//! [`Ring::merge_endpoints`](crate::ring::Ring::merge_endpoints)) so a later
//! reconnect can try a direct LAN `IK` before falling back to the relay (see
//! [`crate::connect`]).
//!
//! The TXT carries only the *fingerprint*, never the transport key or any
//! secret: it is a hint that says "a device claiming this id is reachable here."
//! Authentication still happens in the Noise handshake against the key the ring
//! already holds, so a spoofed announcement can at worst waste a failed
//! connection attempt — it cannot impersonate a peer.
//!
//! # Testability
//!
//! The TXT encode/parse and the endpoint-refresh logic are pure and unit-tested
//! here. The actual [`announce`] / [`browse`] calls need multicast on a real
//! interface, which does not work headless in the sandbox, so they are a
//! **documented manual smoke step** (same posture as FUSE / TUI / two-device
//! real-net) and are exercised by keeperd on a live machine in M5a-4.

use std::collections::HashMap;
use std::net::IpAddr;

use mdns_sd::{Receiver, ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::error::Result;
use crate::ring::Ring;

/// The DNS-SD service type for soft-fig keepers.
pub const SERVICE_TYPE: &str = "_softfig._tcp.local.";

/// TXT key for the device-id fingerprint (hex of the Ed25519 identity pubkey).
pub const TXT_FINGERPRINT: &str = "fp";
/// TXT key for the paired flag (`"1"` paired, `"0"` unpaired).
pub const TXT_PAIRED: &str = "pr";
/// TXT key for the control-plane protocol version.
pub const TXT_VERSION: &str = "v";

/// What this device announces on the LAN.
#[derive(Clone, Debug)]
pub struct Advertisement {
    /// Ed25519 identity public key — the stable device id.
    pub device_id: [u8; 32],
    /// Whether this device has completed pairing (joined a ring).
    pub paired: bool,
    /// The TCP port the keeper's Noise listener is bound to.
    pub port: u16,
}

impl Advertisement {
    /// Lowercase-hex fingerprint of the device id (the TXT `fp` value).
    pub fn fingerprint(&self) -> String {
        hex::encode(self.device_id)
    }

    /// The TXT properties to publish, as a `key -> value` map.
    pub fn txt_properties(&self) -> HashMap<String, String> {
        HashMap::from([
            (TXT_FINGERPRINT.to_string(), self.fingerprint()),
            (
                TXT_PAIRED.to_string(),
                if self.paired { "1" } else { "0" }.to_string(),
            ),
            (TXT_VERSION.to_string(), crate::PROTOCOL_VERSION.to_string()),
        ])
    }
}

/// The identifying fields parsed out of a peer's TXT record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerTxt {
    /// The peer's device-id fingerprint (validated: 64 lowercase hex chars).
    pub fingerprint: String,
    /// Whether the peer advertised itself as paired.
    pub paired: bool,
}

/// A peer resolved on the LAN: its TXT identity plus reachable `host:port`
/// endpoints derived from the resolved addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    pub txt: PeerTxt,
    pub endpoints: Vec<String>,
}

/// Parse a peer's TXT properties into a [`PeerTxt`]. Pure (no mDNS types), so
/// it is unit-tested directly. Returns `None` if the fingerprint is missing or
/// not a 32-byte (64-hex-char) lowercase-hex id — a malformed announcement we
/// simply ignore. A missing/garbled paired flag defaults to `false`.
pub fn parse_txt(props: &HashMap<String, String>) -> Option<PeerTxt> {
    let fingerprint = props.get(TXT_FINGERPRINT)?.to_ascii_lowercase();
    // Must be exactly a 32-byte id in hex, or it is not one of ours.
    if fingerprint.len() != 64 || hex::decode(&fingerprint).is_err() {
        return None;
    }
    let paired = props.get(TXT_PAIRED).map(|v| v == "1").unwrap_or(false);
    Some(PeerTxt { fingerprint, paired })
}

/// Fold a discovered peer's endpoints into the matching ring row (by
/// fingerprint → device id). Returns whether a ring member matched (and was
/// updated). The caller persists the ring afterwards if it wants the endpoints
/// to survive a restart.
pub fn refresh_ring_endpoints(ring: &mut Ring, peer: &DiscoveredPeer) -> bool {
    let Ok(id_bytes) = hex::decode(&peer.txt.fingerprint) else {
        return false;
    };
    let Ok(device_id) = <[u8; 32]>::try_from(id_bytes.as_slice()) else {
        return false;
    };
    ring.merge_endpoints(&device_id, &peer.endpoints)
}

// --- mDNS wrappers (manual smoke; need real multicast) ---------------------

/// Announce this device on the LAN. Returns the registered service fullname,
/// which keeperd retains to [`unregister`](ServiceDaemon::unregister) on lock.
/// `instance_name` is a unique label (e.g. the hostname), `host_name` the mDNS
/// host (e.g. `"my-host.local."`), and `addrs` the interface addresses to
/// publish. **Manual smoke step** — needs multicast on a real interface.
pub fn announce(
    daemon: &ServiceDaemon,
    ad: &Advertisement,
    instance_name: &str,
    host_name: &str,
    addrs: &[IpAddr],
) -> Result<String> {
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        host_name,
        addrs,
        ad.port,
        ad.txt_properties(),
    )?;
    let fullname = info.get_fullname().to_string();
    daemon.register(info)?;
    Ok(fullname)
}

/// Start browsing for soft-fig keepers. Returns the event channel; the caller
/// drains [`ServiceEvent::ServiceResolved`] and feeds each through
/// [`resolved_to_peer`] + [`refresh_ring_endpoints`]. **Manual smoke step.**
pub fn browse(daemon: &ServiceDaemon) -> Result<Receiver<ServiceEvent>> {
    Ok(daemon.browse(SERVICE_TYPE)?)
}

/// Convert a resolved mDNS service into a [`DiscoveredPeer`]: parse its TXT and
/// build `host:port` endpoints from the resolved addresses. Returns `None` if
/// the TXT is not a valid soft-fig announcement.
pub fn resolved_to_peer(svc: &ResolvedService) -> Option<DiscoveredPeer> {
    let mut props = HashMap::new();
    for prop in svc.txt_properties.iter() {
        props.insert(prop.key().to_string(), prop.val_str().to_string());
    }
    let txt = parse_txt(&props)?;
    let endpoints = svc
        .addresses
        .iter()
        .map(|scoped| socket_endpoint(scoped.to_ip_addr(), svc.port))
        .collect();
    Some(DiscoveredPeer { txt, endpoints })
}

/// Render an `IpAddr` + port as a connectable endpoint string, bracketing IPv6.
fn socket_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::static_attestation_message;
    use crate::ring::RingEntry;
    use ed25519_dalek::{Signer, SigningKey};

    fn fingerprint_of(id_seed: u8) -> String {
        hex::encode(SigningKey::from_bytes(&[id_seed; 32]).verifying_key().to_bytes())
    }

    #[test]
    fn advertisement_txt_round_trips_through_parse() {
        let ad = Advertisement {
            device_id: SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes(),
            paired: true,
            port: 9100,
        };
        let parsed = parse_txt(&ad.txt_properties()).expect("valid txt");
        assert_eq!(parsed.fingerprint, ad.fingerprint());
        assert!(parsed.paired);
    }

    #[test]
    fn parse_txt_reads_unpaired_and_defaults_missing_flag() {
        let mut props = HashMap::from([(TXT_FINGERPRINT.to_string(), fingerprint_of(3))]);
        // Explicit unpaired.
        props.insert(TXT_PAIRED.to_string(), "0".to_string());
        assert!(!parse_txt(&props).unwrap().paired);
        // Missing flag → defaults to unpaired, still parses.
        props.remove(TXT_PAIRED);
        assert!(!parse_txt(&props).unwrap().paired);
    }

    #[test]
    fn parse_txt_rejects_missing_or_malformed_fingerprint() {
        // No fingerprint at all.
        assert!(parse_txt(&HashMap::new()).is_none());
        // Not hex.
        let bad = HashMap::from([(TXT_FINGERPRINT.to_string(), "z".repeat(64))]);
        assert!(parse_txt(&bad).is_none());
        // Right charset, wrong length (not a 32-byte id).
        let short = HashMap::from([(TXT_FINGERPRINT.to_string(), "ab".to_string())]);
        assert!(parse_txt(&short).is_none());
    }

    /// A verifiable ring row for a device seeded by `id_seed`/`tk_seed`.
    fn ring_entry(id_seed: u8, tk_seed: u8, name: &str) -> RingEntry {
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
            endpoints: vec![],
            attestation,
            paired_at: 1,
        }
    }

    #[test]
    fn refresh_updates_a_matching_ring_member() {
        let mut ring = Ring::default();
        let entry = ring_entry(1, 2, "laptop");
        let device_id = entry.device_id;
        ring.upsert(entry);

        let peer = DiscoveredPeer {
            txt: PeerTxt {
                fingerprint: hex::encode(device_id),
                paired: true,
            },
            endpoints: vec!["192.168.1.20:9100".into(), "192.168.1.20:9100".into()],
        };
        assert!(refresh_ring_endpoints(&mut ring, &peer));
        // De-duplicated to a single endpoint on the matching row.
        assert_eq!(ring.get(&device_id).unwrap().endpoints, vec!["192.168.1.20:9100"]);
    }

    #[test]
    fn refresh_ignores_a_non_member() {
        let mut ring = Ring::default();
        ring.upsert(ring_entry(1, 2, "laptop"));
        let peer = DiscoveredPeer {
            txt: PeerTxt {
                fingerprint: fingerprint_of(9), // not in the ring
                paired: true,
            },
            endpoints: vec!["10.0.0.5:9100".into()],
        };
        assert!(!refresh_ring_endpoints(&mut ring, &peer));
    }
}
