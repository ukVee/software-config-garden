//! Connection selection: LAN-direct first, relay as fallback.
//!
//! Once a peer is in the ring, reaching it is a routing decision. mDNS
//! discovery ([`crate::discovery`]) populates the ring row's `endpoints` with
//! the peer's current LAN addresses; the relay ([`crate::relay`]) is the
//! always-reachable fallback for when the peer is off-LAN. The policy is the
//! obvious one: **try every known LAN endpoint with a direct Noise `IK`
//! handshake, and only if none answers, go through the relay.** Direct is
//! lower-latency and keeps traffic off the server; the relay always works but
//! costs a round-trip through the middle.
//!
//! This module is deliberately split into a **pure policy** ([`plan_routes`])
//! and a **generic fallback driver** ([`connect_first`]) that takes an `attempt`
//! closure. Keeping the network out of both is what makes the selection
//! unit-testable headless; keeperd (M5a-4) supplies the closure that actually
//! TCP-connects + runs [`ik_initiator`](crate::transport::ik_initiator) for a
//! [`Route::Direct`] or [`relay_connect`](crate::relay::relay_connect) for
//! [`Route::Relay`], choosing how to unify the two resulting session types
//! (e.g. by handling each inline, or boxing the IO).

use crate::error::{NetError, Result};
use crate::ring::RingEntry;

/// One way to reach a peer, in priority order from [`plan_routes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// A direct LAN connection to this `host:port` (from mDNS / the ring),
    /// established with a Noise `IK` handshake keyed by the peer's stored static.
    Direct(String),
    /// Reach the peer through the relay (the peer is registered there).
    Relay,
}

/// Build the ordered list of routes to try for `peer`: each known LAN endpoint
/// as a [`Route::Direct`] (in ring order), then [`Route::Relay`] iff a relay is
/// configured. An empty result means the peer is currently unreachable (no
/// endpoints discovered and no relay) — the caller should surface that, not
/// silently succeed.
pub fn plan_routes(peer: &RingEntry, relay_available: bool) -> Vec<Route> {
    let mut routes: Vec<Route> = peer.endpoints.iter().cloned().map(Route::Direct).collect();
    if relay_available {
        routes.push(Route::Relay);
    }
    routes
}

/// Try each route in order, returning the first `attempt` that succeeds. On an
/// all-routes failure, returns the **last** error (the relay's, when a relay was
/// tried last) so the caller surfaces the most-fallback failure; on an empty
/// route list, returns a "no route" protocol error. The peer-reachability
/// policy lives in [`plan_routes`]; this only drives the fallback.
pub fn connect_first<T, F>(routes: &[Route], mut attempt: F) -> Result<T>
where
    F: FnMut(&Route) -> Result<T>,
{
    let mut last_err: Option<NetError> = None;
    for route in routes {
        match attempt(route) {
            Ok(value) => return Ok(value),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(NetError::Protocol("no route to peer (no endpoints, no relay)")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::static_attestation_message;
    use ed25519_dalek::{Signer, SigningKey};

    fn peer_with(endpoints: &[&str]) -> RingEntry {
        let id = SigningKey::from_bytes(&[1u8; 32]);
        let transport_pubkey =
            x25519_dalek::x25519([2u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let attestation = id
            .sign(&static_attestation_message(&transport_pubkey))
            .to_bytes();
        RingEntry {
            device_id: id.verifying_key().to_bytes(),
            name: "peer".into(),
            transport_pubkey,
            endpoints: endpoints.iter().map(|s| s.to_string()).collect(),
            attestation,
            paired_at: 1,
        }
    }

    #[test]
    fn lan_endpoints_come_before_relay() {
        let peer = peer_with(&["192.168.1.20:9100", "10.0.0.5:9100"]);
        assert_eq!(
            plan_routes(&peer, true),
            vec![
                Route::Direct("192.168.1.20:9100".into()),
                Route::Direct("10.0.0.5:9100".into()),
                Route::Relay,
            ]
        );
    }

    #[test]
    fn no_endpoints_falls_back_to_relay_only() {
        assert_eq!(plan_routes(&peer_with(&[]), true), vec![Route::Relay]);
    }

    #[test]
    fn no_endpoints_and_no_relay_is_unreachable() {
        assert!(plan_routes(&peer_with(&[]), false).is_empty());
    }

    #[test]
    fn direct_only_when_relay_absent() {
        assert_eq!(
            plan_routes(&peer_with(&["192.168.1.20:9100"]), false),
            vec![Route::Direct("192.168.1.20:9100".into())]
        );
    }

    #[test]
    fn connect_first_falls_back_to_relay_when_direct_fails() {
        let peer = peer_with(&["192.168.1.20:9100"]);
        let routes = plan_routes(&peer, true);
        let mut tried = Vec::new();

        let result = connect_first(&routes, |route| {
            tried.push(route.clone());
            match route {
                Route::Direct(_) => Err(NetError::Protocol("LAN unreachable")),
                Route::Relay => Ok("via-relay"),
            }
        });

        assert_eq!(result.unwrap(), "via-relay");
        // Direct was tried before the relay.
        assert_eq!(
            tried,
            vec![Route::Direct("192.168.1.20:9100".into()), Route::Relay]
        );
    }

    #[test]
    fn connect_first_stops_at_the_first_success() {
        let peer = peer_with(&["192.168.1.20:9100"]);
        let routes = plan_routes(&peer, true);
        let mut attempts = 0;

        let result = connect_first(&routes, |route| {
            attempts += 1;
            match route {
                Route::Direct(_) => Ok("via-lan"),
                Route::Relay => panic!("relay must not be attempted after a direct success"),
            }
        });

        assert_eq!(result.unwrap(), "via-lan");
        assert_eq!(attempts, 1);
    }

    #[test]
    fn connect_first_reports_last_error_when_all_routes_fail() {
        let peer = peer_with(&["192.168.1.20:9100"]);
        let routes = plan_routes(&peer, true);
        let result: Result<&str> =
            connect_first(&routes, |_| Err(NetError::Protocol("nope")));
        assert!(result.is_err());
    }

    #[test]
    fn connect_first_on_empty_routes_is_no_route() {
        let result: Result<&str> = connect_first(&[], |_| Ok("unreachable"));
        assert!(matches!(result, Err(NetError::Protocol(_))));
    }
}
