//! Commit canonical form, hashing, and signing.
//!
//! The canonical commit is a JCS-canonicalized JSON object covering every
//! field that contributes to identity:
//!
//! ```json
//! {
//!   "author_device": "...",
//!   "author_pubkey": "<hex 32B>",
//!   "chain_id":      "<ref_name>",   // OPTIONAL — omitted for the device chain
//!   "intent":        "<closed-enum name>",
//!   "master_key_id": <u32>,
//!   "parent":        "<hex 32B>" | null,
//!   "payload":       <object>,
//!   "root_tree":     "<hex 32B>",
//!   "timestamp":     <i64 unix seconds>
//! }
//! ```
//!
//! `chain_id` binds a commit to *its* chain (M5d slice 002). A shared-subtree
//! commit carries `chain_id = <ref_name>` (the stable chain ref, e.g.
//! `chain/proj` — invariant across key rotation, unlike `master_key_id`), so a
//! commit signed for chain A can never be replayed as a valid commit on chain
//! B. The device chain (`TIP_REF`) omits the field entirely, keeping every
//! pre-M5d device-chain hash byte-identical — `None` ⇒ the key is not written,
//! so the canonical bytes are indistinguishable from the historical form.
//!
//! `commit_hash = BLAKE3(canonical_commit_bytes(...))`.
//! `signature   = identity.sign(commit_hash)`.
//!
//! Verifiers re-canonicalize, re-hash, and check both the hash matches
//! the row's `hash` column and the signature verifies under the row's
//! `author_pubkey`.

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use softfig_store::Hash;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone)]
pub struct CanonicalCommit<'a> {
    pub parent: Option<Hash>,
    pub root_tree: Hash,
    pub author_device: &'a str,
    pub author_pubkey: [u8; 32],
    pub timestamp: i64,
    pub intent: &'a str,
    pub payload: &'a Value,
    pub master_key_id: u32,
    /// The owning chain's stable ref name (M5d slice 002). `None` for the
    /// device chain (`TIP_REF`) — the field is then omitted from the canonical
    /// form so device-chain hashes stay byte-identical to the pre-M5d shape.
    /// `Some(ref_name)` for a shared subtree, binding the commit to its chain.
    pub chain_id: Option<&'a str>,
}

impl<'a> CanonicalCommit<'a> {
    pub fn to_json(&self) -> Value {
        let mut obj = json!({
            "author_device": self.author_device,
            "author_pubkey": hex::encode(self.author_pubkey),
            "intent":        self.intent,
            "master_key_id": self.master_key_id,
            "parent":        self.parent.map(|h| h.to_hex()),
            "payload":       self.payload,
            "root_tree":     self.root_tree.to_hex(),
            "timestamp":     self.timestamp,
        });
        // Omit `chain_id` entirely when absent so the device chain (and every
        // pre-M5d commit) canonicalizes to identical bytes — inserting a `null`
        // would shift the hash. JCS re-sorts keys, so insertion order here is
        // irrelevant to the output.
        if let Some(chain_id) = self.chain_id {
            obj["chain_id"] = Value::String(chain_id.to_string());
        }
        obj
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_jcs::to_vec(&self.to_json())?)
    }

    pub fn hash(&self) -> Result<Hash> {
        Ok(Hash::of(&self.canonical_bytes()?))
    }
}

/// Verify a stored commit row against its declared hash + signature.
pub fn verify_commit(
    canon: &CanonicalCommit<'_>,
    declared_hash: Hash,
    signature: &[u8; 64],
) -> Result<()> {
    let derived = canon.hash()?;
    if derived != declared_hash {
        return Err(CoreError::CommitHashMismatch {
            row: declared_hash,
            derived,
        });
    }
    let vk = VerifyingKey::from_bytes(&canon.author_pubkey)?;
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(declared_hash.as_bytes(), &sig)
        .map_err(|_| CoreError::BadSignature(declared_hash))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Fixed inputs shared across the golden/binding/replay tests so the device
    // form is a stable, reproducible target.
    fn fixed_payload() -> Value {
        serde_json::json!({ "msg": "garden initialized" })
    }

    fn base<'a>(payload: &'a Value, chain_id: Option<&'a str>) -> CanonicalCommit<'a> {
        CanonicalCommit {
            parent: None,
            root_tree: Hash::of(b"root-tree-fixed"),
            author_device: "host",
            author_pubkey: [7u8; 32],
            timestamp: 1_700_000_000,
            intent: "init",
            payload,
            master_key_id: 1,
            chain_id,
        }
    }

    /// GOLDEN: a device-chain commit (`chain_id = None`) omits the key entirely,
    /// so its canonical bytes are byte-identical to the pre-M5d form, and its
    /// hash is pinned to a fixed value. If a future field is added to `to_json`
    /// unconditionally (or `None` starts emitting a key), both assertions fail —
    /// catching a silent device-hash shift that would break cross-version verify.
    #[test]
    fn device_chain_canonical_bytes_omit_chain_id_and_hash_is_stable() {
        let payload = fixed_payload();
        let canon = base(&payload, None);

        // The canonical bytes must equal the JCS of an object built WITHOUT any
        // `chain_id` key — i.e. the historical shape, reconstructed explicitly.
        let expected = serde_json::json!({
            "author_device": "host",
            "author_pubkey": hex::encode([7u8; 32]),
            "intent":        "init",
            "master_key_id": 1,
            "parent":        Value::Null,
            "payload":       fixed_payload(),
            "root_tree":     Hash::of(b"root-tree-fixed").to_hex(),
            "timestamp":     1_700_000_000,
        });
        assert_eq!(
            canon.canonical_bytes().unwrap(),
            serde_jcs::to_vec(&expected).unwrap(),
            "device-chain form must omit chain_id and match the pre-M5d bytes"
        );
        assert!(
            !String::from_utf8(canon.canonical_bytes().unwrap())
                .unwrap()
                .contains("chain_id"),
            "chain_id must not appear in device-chain canonical bytes"
        );

        // Pinned golden hash of the fixed device-chain form.
        assert_eq!(
            canon.hash().unwrap().to_hex(),
            "046dd04123ffc3e4d2702c38896d9a1bb9e0b99771274f755ea7e976d63b1d76",
            "device-chain golden hash drifted — a field add shifted device hashes"
        );
    }

    /// BINDING: the same commit canonicalizes to distinct hashes under different
    /// chains, and both differ from the device (`None`) form.
    #[test]
    fn chain_id_binds_the_hash() {
        let payload = fixed_payload();
        let dev = base(&payload, None).hash().unwrap();
        let a = base(&payload, Some("chain/a")).hash().unwrap();
        let b = base(&payload, Some("chain/b")).hash().unwrap();
        assert_ne!(a, b, "distinct chains must produce distinct hashes");
        assert_ne!(a, dev, "a keyed chain must differ from the device form");
        assert_ne!(b, dev, "a keyed chain must differ from the device form");
    }

    /// CROSS-CHAIN REPLAY: a commit signed for chain A fails `verify_commit`
    /// when re-canonicalized as chain B — the signature is valid but the hash it
    /// covers no longer matches, so a shared-chain commit can't be lifted onto
    /// another chain.
    #[test]
    fn commit_signed_for_chain_a_fails_verify_as_chain_b() {
        let payload = fixed_payload();
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();

        let mut canon_a = base(&payload, Some("chain/a"));
        canon_a.author_pubkey = pubkey;
        let hash_a = canon_a.hash().unwrap();
        let sig = sk.sign(hash_a.as_bytes()).to_bytes();

        // Same commit is valid when checked as chain A.
        assert!(verify_commit(&canon_a, hash_a, &sig).is_ok());

        // Re-labelling it as chain B (declared hash + signature unchanged) fails
        // at the hash-reconstruction step: chain B canonicalizes to a different
        // hash than the declared one.
        let mut canon_b = base(&payload, Some("chain/b"));
        canon_b.author_pubkey = pubkey;
        let err = verify_commit(&canon_b, hash_a, &sig).unwrap_err();
        assert!(
            matches!(err, CoreError::CommitHashMismatch { .. }),
            "cross-chain replay must fail as a hash mismatch, got {err:?}"
        );
    }
}
