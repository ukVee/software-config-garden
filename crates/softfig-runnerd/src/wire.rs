//! The runner's job listener (spec remote-runner §3.3, §6): one Noise
//! connection per job, requester device key <-> runner key.
//!
//! runnerd binds a TCP listener on its own port and, for each connection, runs
//! the runner handshake ([`softfig_net::runner_responder`] — `XX` on first
//! contact, `IK` on reconnect, discriminated by the first-message length),
//! presenting the delegated runner certificate in the handshake payload. It
//! then verifies the requester (self-attestation binding identity to the
//! handshake static + the `accept.toml` allowlist), advertises [`RunnerCaps`],
//! reads the signed [`JobOffer`], and replies [`JobAccept`] / [`JobReject`]
//! with spec §6's closed reason enum.
//!
//! There is **no real execution yet** (slice 003): an accepted offer gets a
//! canned [`JobResult`] from a stub executor, so the wire can be tested end to
//! end on its own. The runner never reads a garden; its trust material is the
//! `cert.toml` + `accept.toml` + `serve.toml` in its own state root.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use softfig_net::proto::{frame, Frame, JobAccept, JobReject, JobResult, RunnerCaps, RunnerHandshake, SourceHave};
use softfig_source::SourceBackend;

use crate::cert::StoredCert;
use crate::config::{AcceptConfig, ServeConfig};
use crate::error::{Error, Result};
use crate::keys::RunnerKeys;
use crate::state::StateRoot;

/// The runner's job listener. Owns its `TcpListener` and the long-lived
/// transport static; the certificate and the `accept.toml` / `serve.toml`
/// configs are reloaded per connection, so a grant / revoke / apply /
/// disable takes effect on the next connection without restarting.
pub struct WireServer {
    listener: TcpListener,
    root: StateRoot,
    transport_secret: [u8; 32],
}

impl WireServer {
    /// Bind the job listener on `addr`, loading the runner's transport static.
    /// Fails if the keys have not been generated (a not-yet-enabled runner).
    pub fn bind(root: StateRoot, addr: &str) -> Result<Self> {
        let keys = RunnerKeys::load(&root.keys_dir())?;
        let listener = TcpListener::bind(addr).map_err(|e| {
            Error::Protocol(format!("could not bind the runner listener on {addr}: {e}"))
        })?;
        Ok(Self {
            listener,
            root,
            transport_secret: *keys.transport_secret(),
        })
    }

    /// The bound address (useful for tests and for the mDNS announce).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// The underlying listener, so tests can bound an accept with
    /// `softfig_net::testing::accept_within`.
    pub fn listener(&self) -> &TcpListener {
        &self.listener
    }

    /// Accept one connection. Exposed so tests can drive the server side
    /// deterministically; production uses [`run`](Self::run).
    pub fn accept(&self) -> Result<TcpStream> {
        Ok(self.listener.accept()?.0)
    }

    /// Run the accept loop, serving each connection on its own thread
    /// (thread-per-connection, matching `softfig-net`'s concurrency model).
    pub fn run(self: Arc<Self>) -> Result<()> {
        for conn in self.listener.incoming() {
            let conn = conn?;
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_connection(conn);
            });
        }
        Ok(())
    }

    /// Serve one connection: handshake, requester verification, caps, offer,
    /// accept/reject, and the stub result. Errors are per-connection (the
    /// caller drops them); a refused requester sees a `JobReject`, and a failed
    /// handshake / attestation sees the connection close.
    pub fn serve_connection(&self, stream: TcpStream) -> Result<()> {
        let cert = StoredCert::load(&self.root.cert_toml())
            .map_err(|_| Error::Protocol("runner has no certificate (run `softfig runner enable`)".into()))?;
        let handshake = build_runner_handshake(&cert)?;

        let mut session = softfig_net::runner_responder(stream, &self.transport_secret, &handshake)?;

        // Verify the requester's identity<->static binding before trusting the
        // claimed device_id for the allowlist + signature checks.
        let device_id = self.verify_requester(&session)?;

        let accept = AcceptConfig::load(&self.root.accept_toml())?;
        let serve = ServeConfig::load(&self.root.serve_toml())?;

        // Advertise capabilities (public), then read the offer.
        session.send_frame(&Frame::runner_caps(self.runner_caps(&serve)))?;
        let offer = match session.recv_frame()?.kind {
            Some(frame::Kind::JobOffer(o)) => o,
            _ => return Err(Error::Protocol("expected JobOffer".into())),
        };

        match self.authorize(&offer, &device_id, session.peer_static(), &accept, &serve) {
            None => {
                session.send_frame(&Frame::job_accept(JobAccept {
                    job_id: offer.job_id.clone(),
                    queue_pos: 0,
                }))?;
                // Slice 004: the source step — negotiate have/want, read the
                // bundle, ingest + verify (rejecting `source-mismatch`), and
                // materialize. Real execution lands in slice 006.
                self.serve_source(&mut session, &offer)?;
            }
            Some(reason) => {
                session.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id,
                    reason: reason.to_u32(),
                }))?;
            }
        }
        Ok(())
    }

    /// Verify the requester's self-attestation (its identity key signed its
    /// handshake static) and return its claimed device id. A failure closes the
    /// connection (the peer cannot prove who it is).
    fn verify_requester(&self, session: &softfig_net::NoiseSession<TcpStream>) -> Result<[u8; 32]> {
        let hello = session.peer_hello();
        let device_id: [u8; 32] = hello
            .device_id
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("requester device_id wrong length".into()))?;
        let attestation: [u8; 64] = hello
            .static_attestation
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("requester attestation wrong length".into()))?;
        if !softfig_net::verify_static_attestation(&device_id, session.peer_static(), &attestation) {
            return Err(Error::Protocol("requester attestation does not verify".into()));
        }
        Ok(device_id)
    }

    /// Decide accept vs reject for an offer. The order of checks is the closed
    /// reason list: disabled first, then the allowlist (identity + static), then
    /// the offer signature against the granted identity.
    fn authorize(
        &self,
        offer: &softfig_net::proto::JobOffer,
        device_id: &[u8; 32],
        peer_static: &[u8; 32],
        accept: &AcceptConfig,
        serve: &ServeConfig,
    ) -> Option<softfig_net::JobRejectReason> {
        if !serve.enabled {
            return Some(softfig_net::JobRejectReason::Disabled);
        }
        let Some(granted) = accept
            .peer
            .iter()
            .find(|p| p.device_id == hex::encode(device_id))
        else {
            return Some(softfig_net::JobRejectReason::NotGranted);
        };
        // The handshake static must be the one `grant` recorded for this
        // identity, and the offer must be signed by that identity.
        if hex::decode(&granted.transport_pubkey).ok().as_deref() != Some(peer_static) {
            return Some(softfig_net::JobRejectReason::NotGranted);
        }
        if !softfig_net::verify_offer_sig(offer, device_id, &offer.signature) {
            return Some(softfig_net::JobRejectReason::NotGranted);
        }
        None
    }

    /// Advertise this runner's capabilities (spec §11 frame 300). Placeholder
    /// where the field needs a dependency not yet present; slice 006/007 fill
    /// the real values.
    fn runner_caps(&self, serve: &ServeConfig) -> RunnerCaps {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(0);
        RunnerCaps {
            arch: std::env::consts::ARCH.to_string(),
            triple: String::new(),
            cores,
            mem_bytes: 0,
            toolchains: serve.toolchains.clone(),
            max_jobs: serve.max_jobs,
            active_jobs: 0,
            power: "unknown".into(),
        }
    }
    /// Serve the source step for an accepted job (spec §4.3): advertise the
    /// have/want tips, read the bundle chunks, ingest + verify (a tree mismatch
    /// is a `source-mismatch` [`JobReject`]), then materialize into a scratch
    /// dir and return the stub result. The sandbox-wrapped ingest/materialize
    /// and the real run step land in slice 006; here the git calls run under
    /// `softfig_source`'s hardening config (hooks off, no network, fsck on).
    fn serve_source(
        &self,
        session: &mut softfig_net::NoiseSession<TcpStream>,
        offer: &softfig_net::proto::JobOffer,
    ) -> Result<()> {
        let source_id = softfig_source::SourceId::decode(&offer.source_id)
            .ok_or_else(|| Error::Protocol("malformed source id in offer".into()))?;
        let repo_key: [u8; 32] = offer
            .repo_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protocol("repo_key wrong length".into()))?;
        let backend = softfig_source::GitBackend::new(self.root.repos_dir());

        let haves = backend
            .negotiate(&repo_key)
            .map_err(|e| Error::Protocol(format!("negotiate failed: {e}")))?;
        session.send_frame(&Frame::source_have(SourceHave {
            repo_key: offer.repo_key.clone(),
            tips: haves.tips,
            recent_commits: haves.commits,
        }))?;

        // Read the bundle chunks until the `last` flag.
        let mut bundle = Vec::new();
        loop {
            match session.recv_frame()?.kind {
                Some(frame::Kind::SourceChunk(c)) => {
                    bundle.extend_from_slice(&c.payload);
                    if c.last {
                        break;
                    }
                }
                _ => return Err(Error::Protocol("expected SourceChunk during transfer".into())),
            }
        }

        backend
            .ingest(&repo_key, &source_id, &bundle)
            .map_err(|e| Error::Protocol(format!("ingest failed: {e}")))?;
        if let Err(e) = backend.verify(&repo_key, &source_id, &offer.snapshot_commit) {
            if matches!(e, softfig_source::Error::SourceMismatch(_)) {
                session.send_frame(&Frame::job_reject(JobReject {
                    job_id: offer.job_id.clone(),
                    reason: softfig_net::JobRejectReason::SourceMismatch.to_u32(),
                }))?;
                return Ok(());
            }
            return Err(Error::Protocol(format!("verify failed: {e}")));
        }

        // Materialize into a scratch dir (slice 006 replaces this with the
        // job's sandboxed `/src`); this proves the read-tree/checkout-index
        // path end to end against the hostile-tree hardening.
        let scratch = tempfile::tempdir()?;
        backend
            .materialize(
                &repo_key,
                &source_id,
                &offer.snapshot_commit,
                scratch.path(),
                false,
            )
            .map_err(|e| Error::Protocol(format!("materialize failed: {e}")))?;

        // Stub result: the real run step + signed attestation land in slice 006.
        session.send_frame(&Frame::job_result(JobResult {
            job_id: offer.job_id.clone(),
            exit_code: 0,
            attestation: Vec::new(),
        }))?;
        Ok(())
    }
}

/// Build the in-handshake [`RunnerHandshake`] from the stored certificate
/// (hex-string form) plus its signature.
fn build_runner_handshake(cert: &StoredCert) -> Result<RunnerHandshake> {
    let rc = softfig_net::proto::RunnerCert {
        device_id: decode_hex(&cert.device_id, "cert device_id")?.to_vec(),
        runner_transport_pubkey: decode_hex(&cert.runner_transport_pubkey, "cert transport key")?
            .to_vec(),
        runner_attest_pubkey: decode_hex(&cert.runner_attest_pubkey, "cert attest key")?.to_vec(),
        serial: decode_hex(&cert.serial, "cert serial")?.to_vec(),
        issued_at: cert.issued_at,
        expires_at: cert.expires_at,
    };
    let signature = decode_hex(&cert.signature, "cert signature")?.to_vec();
    Ok(RunnerHandshake {
        cert: Some(rc),
        signature,
    })
}

/// Decode a lowercase-hex field into a byte vector, mapping a malformed or
/// wrong-length value to a `Malformed` error naming the field.
fn decode_hex(s: &str, what: &'static str) -> Result<Vec<u8>> {
    hex::decode(s.trim()).map_err(|e| Error::malformed(what, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::StoredCert;
    use crate::state::StateRoot;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex_id(id: &SigningKey) -> String {
        hex::encode(id.verifying_key().to_bytes())
    }

    #[test]
    fn build_handshake_decodes_hex_cert() {
        let id = SigningKey::from_bytes(&[1u8; 32]);
        let cert = StoredCert {
            device_id: hex_id(&id),
            runner_transport_pubkey: "ab".repeat(32),
            runner_attest_pubkey: "cd".repeat(32),
            serial: "ef".repeat(16),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_000 + 90 * 24 * 60 * 60,
            signature: "11".repeat(64),
        };
        let h = build_runner_handshake(&cert).unwrap();
        let c = h.cert.unwrap();
        assert_eq!(c.device_id, id.verifying_key().to_bytes().to_vec());
        assert_eq!(c.serial, vec![0xef; 16]);
        assert_eq!(h.signature, vec![0x11; 64]);
    }

    #[test]
    fn build_handshake_rejects_malformed_hex() {
        let cert = StoredCert {
            device_id: "zz".repeat(32),
            runner_transport_pubkey: "ab".repeat(32),
            runner_attest_pubkey: "cd".repeat(32),
            serial: "ef".repeat(16),
            issued_at: 0,
            expires_at: 0,
            signature: "11".repeat(64),
        };
        assert!(build_runner_handshake(&cert).is_err());
    }

    #[test]
    fn bind_generates_address_and_loads_keys() {
        let dir = tempfile::tempdir().unwrap();
        let root = StateRoot::new(dir.path());
        root.ensure_dirs().unwrap();
        RunnerKeys::generate().persist(&root.keys_dir()).unwrap();
        let server = WireServer::bind(root, "127.0.0.1:0").unwrap();
        assert!(server.local_addr().unwrap().port() != 0);
    }

    #[test]
    fn authorize_order_and_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let server = {
            let root = StateRoot::new(dir.path());
            root.ensure_dirs().unwrap();
            RunnerKeys::generate().persist(&root.keys_dir()).unwrap();
            WireServer::bind(root, "127.0.0.1:0").unwrap()
        };

        let id = SigningKey::from_bytes(&[2u8; 32]);
        let device_id = id.verifying_key().to_bytes();
        let static_ = [3u8; 32];

        let mut serve = ServeConfig::default(); // enabled: false
        let empty = AcceptConfig::default();
        let mut offer = softfig_net::proto::JobOffer {
            signature: vec![0u8; 64],
            ..Default::default()
        };

        // Disabled wins.
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &empty, &serve),
            Some(softfig_net::JobRejectReason::Disabled)
        );

        serve.enabled = true;
        // Not granted wins when enabled but absent from the allowlist.
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &empty, &serve),
            Some(softfig_net::JobRejectReason::NotGranted)
        );

        // Granted with the right static but an unsigned offer: still refused.
        let mut accept = AcceptConfig::default();
        accept.grant(crate::config::AcceptedPeer {
            device_id: hex::encode(device_id),
            transport_pubkey: hex::encode(static_),
            name: "tablet".into(),
        });
        assert_eq!(
            server.authorize(&offer, &device_id, &static_, &accept, &serve),
            Some(softfig_net::JobRejectReason::NotGranted)
        );

        // A valid offer (signed by the granted identity) is accepted.
        offer.signature = id.sign(&softfig_net::offer_signing_bytes(&offer)).to_bytes().to_vec();
        assert_eq!(server.authorize(&offer, &device_id, &static_, &accept, &serve), None);
    }
}
