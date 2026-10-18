//! The signed canonical-JSON job attestation (spec remote-runner §8).
//!
//! `JobAttestation` is canonical (JCS-sorted) JSON, reusing the VCS's
//! `serde_jcs` canonicalizer (never a second one), signed by the runner's
//! Ed25519 attest key under the domain `softfig/runner/attestation/v1`.
//!
//! The signing message is the domain byte-prefix followed by
//! `BLAKE3(canonical_bytes)` — the same "sign the canonical digest" shape as a
//! VCS commit signature, with a domain prefix so an attestation signature can
//! never be confused with a commit signature (which signs a bare 32-byte
//! digest under the *identity* key) or any other use of the attest key.

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Domain-separation prefix for the attestation signing message. Versioned so a
/// future attestation scheme can coexist; distinct from the runner-certificate
/// domain (`softfig/runner/delegation/v1`) and every commit-signature context.
pub const ATTEST_DOMAIN: &[u8] = b"softfig/runner/attestation/v1";

/// The typed source id (spec §4.5) as it appears in the attestation: the hash
/// format, the tree root, and the snapshot commit it was built from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub format: String,
    pub root: String,
    pub commit: String,
}

/// The toolchain the runner used (spec §8): the `rustc` version line, the host
/// target triple, and the libc. Empty strings mean "unknown" (no rustc on the
/// runner, or a cap-killed payload that never wrote a report).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainInfo {
    pub rustc: String,
    pub host_triple: String,
    pub libc: String,
}

/// One name/value environment binding. The attestation sorts these by name so
/// the canonical form is independent of insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvBinding {
    pub name: String,
    pub value: String,
}

/// The job's exit: exactly one of `code` (a normal exit), `signal` (the run
/// step was signal-killed), or `reason` (a resource-cap kill, e.g. "time").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitInfo {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signal: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

impl ExitInfo {
    /// A normal exit code.
    pub fn code(code: i32) -> Self {
        Self { code: Some(code), signal: None, reason: None }
    }

    /// A signal-killed run step.
    pub fn signal(signal: i32) -> Self {
        Self { code: None, signal: Some(signal), reason: None }
    }

    /// A resource-cap kill (reason is `CapsHit::as_str()`: "time" | "memory").
    pub fn reason(reason: &str) -> Self {
        Self { code: None, signal: None, reason: Some(reason.to_string()) }
    }
}

/// One collected artifact (spec §8): path, size, BLAKE3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub size: u64,
    pub blake3: String,
}

/// The attestation object (spec §8). Binary fields are lowercase hex; `env` is
/// sorted by name; `sandbox_policy` is the hex BLAKE3 of the resolved run
/// policy (`None` when the offer named no command, so no run step happened).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAttestation {
    pub job_id: String,
    pub requester_device: String,
    pub runner_device: String,
    pub runner_cert_serial: String,
    pub source: SourceRef,
    pub repo_key: String,
    pub profile: String,
    pub cmd: Vec<String>,
    pub env: Vec<EnvBinding>,
    pub network: String,
    pub cache: String,
    pub toolchain: ToolchainInfo,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sandbox_policy: Option<String>,
    pub exit: ExitInfo,
    pub started_at: i64,
    pub finished_at: i64,
    pub artifacts: Vec<ArtifactEntry>,
    pub log_blake3: String,
}

impl JobAttestation {
    /// The canonical (JCS-sorted) bytes this attestation signs over.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_jcs::to_vec(self).map_err(Error::from)
    }

    /// `BLAKE3(canonical_bytes)` — the fixed 32-byte digest the signature
    /// covers, and what §6 step 9 records as `attestation_hash`.
    pub fn hash(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }

    /// The exact bytes the attest key signs: the domain prefix followed by the
    /// canonical digest (see the module doc).
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let mut msg = Vec::with_capacity(ATTEST_DOMAIN.len() + 32);
        msg.extend_from_slice(ATTEST_DOMAIN);
        msg.extend_from_slice(&self.hash()?);
        Ok(msg)
    }

    /// Sign with the runner's attest key.
    pub fn sign(&self, signing_key: &ed25519_dalek::SigningKey) -> Result<[u8; 64]> {
        Ok(signing_key.sign(&self.signing_message()?).to_bytes())
    }

    /// Verify a signature over this attestation under the runner's attest key.
    /// Never panics — a bad key, bad signature, or a non-verifying signature all
    /// return `false`.
    pub fn verify(&self, attest_pubkey: &[u8; 32], signature: &[u8; 64]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(attest_pubkey) else {
            return false;
        };
        let Ok(msg) = self.signing_message() else {
            return false;
        };
        vk.verify(&msg, &Signature::from_bytes(signature)).is_ok()
    }
}

/// A signed attestation as carried in `JobResult.attestation`: the attestation
/// plus the attest key's signature (lowercase hex). The signature covers the
/// [`JobAttestation::signing_message`] bytes, not this container — the container
/// is the transport wrapper and is plain JSON, not itself canonical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: JobAttestation,
    pub signature: String,
}

impl SignedAttestation {
    /// Serialize to the `JobResult.attestation` bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }

    /// Parse from `JobResult.attestation` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Error::from)
    }

    /// Verify the signature against the runner's attest public key (from the
    /// requester's cached certificate). Never panics.
    pub fn verify(&self, attest_pubkey: &[u8; 32]) -> bool {
        let Some(sig) = hex::decode(self.signature.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
        else {
            return false;
        };
        self.attestation.verify(attest_pubkey, &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Verifier};

    fn attestation() -> JobAttestation {
        JobAttestation {
            job_id: "ab".repeat(16),
            requester_device: "cd".repeat(32),
            runner_device: "ef".repeat(32),
            runner_cert_serial: "11".repeat(16),
            source: SourceRef {
                format: "git-sha1".into(),
                root: "aa".repeat(20),
                commit: "bb".repeat(20),
            },
            repo_key: "cc".repeat(32),
            profile: "gate".into(),
            cmd: vec!["cargo".into(), "test".into()],
            env: vec![
                EnvBinding { name: "B".into(), value: "2".into() },
                EnvBinding { name: "A".into(), value: "1".into() },
            ],
            network: "none".into(),
            cache: "shared".into(),
            toolchain: ToolchainInfo {
                rustc: "1.85.0".into(),
                host_triple: "x86_64-unknown-linux-gnu".into(),
                libc: "gnu".into(),
            },
            sandbox_policy: Some("dd".repeat(32)),
            exit: ExitInfo::code(0),
            started_at: 1_800_000_000,
            finished_at: 1_800_000_100,
            artifacts: vec![ArtifactEntry {
                path: "target/release/softfig".into(),
                size: 42,
                blake3: "ee".repeat(32),
            }],
            log_blake3: "ff".repeat(32),
        }
    }

    #[test]
    fn canonical_bytes_are_jcs_sorted_and_deterministic() {
        let a = attestation();
        // Canonical JSON sorts object keys: `job_id` is not alphabetically
        // first, so the canonical form must start with a sorted key (e.g.
        // "artifacts") rather than the struct's field order.
        let bytes = a.canonical_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("{\"artifacts\""), "canonical JSON must sort keys: {text}");
        // Deterministic across two calls.
        assert_eq!(bytes, a.canonical_bytes().unwrap());
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let a = attestation();
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let sig = a.sign(&sk).unwrap();
        assert!(a.verify(&pubkey, &sig));
    }

    #[test]
    fn tampered_attestation_is_rejected() {
        let a = attestation();
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let sig = a.sign(&sk).unwrap();

        // Flip one bit of a field: the digest changes, the signature no longer
        // verifies.
        let mut tampered = a.clone();
        tampered.exit = ExitInfo::code(1);
        assert!(!tampered.verify(&pubkey, &sig));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let a = attestation();
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let sig = a.sign(&sk).unwrap();
        let other = SigningKey::from_bytes(&[10u8; 32]).verifying_key().to_bytes();
        assert!(!a.verify(&other, &sig));
    }

    #[test]
    fn signed_attestation_round_trips_and_verifies() {
        let a = attestation();
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let sig = a.sign(&sk).unwrap();
        let signed = SignedAttestation { attestation: a.clone(), signature: hex::encode(sig) };

        let bytes = signed.to_bytes().unwrap();
        let parsed = SignedAttestation::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, signed);
        assert!(parsed.verify(&pubkey));

        // Tamper the wrapped attestation, re-encode, re-parse: still fails.
        let mut bad = parsed.clone();
        bad.attestation.exit = ExitInfo::code(1);
        let bad_bytes = bad.to_bytes().unwrap();
        let bad_parsed = SignedAttestation::from_bytes(&bad_bytes).unwrap();
        assert!(!bad_parsed.verify(&pubkey));
    }

    #[test]
    fn domain_separates_attestation_from_a_bare_digest_signature() {
        // A signature over the bare digest (a commit-shaped signature) must not
        // verify as an attestation signature, because the attestation signs
        // `domain || digest`.
        let a = attestation();
        let sk = SigningKey::from_bytes(&[12u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let digest = a.hash().unwrap();
        let bare_sig = sk.sign(&digest).to_bytes();
        assert!(!a.verify(&pubkey, &bare_sig));
        // Sanity: the verifier agrees the bare signature is valid over the bare
        // digest, so the failure above is genuinely the domain, not the key.
        let vk = VerifyingKey::from_bytes(&pubkey).unwrap();
        assert!(vk.verify(&digest, &Signature::from_bytes(&bare_sig)).is_ok());
    }
}
