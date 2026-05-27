//! Commit canonical form, hashing, and signing.
//!
//! The canonical commit is a JCS-canonicalized JSON object covering every
//! field that contributes to identity:
//!
//! ```json
//! {
//!   "author_device": "...",
//!   "author_pubkey": "<hex 32B>",
//!   "intent":        "<closed-enum name>",
//!   "master_key_id": <u32>,
//!   "parent":        "<hex 32B>" | null,
//!   "payload":       <object>,
//!   "root_tree":     "<hex 32B>",
//!   "timestamp":     <i64 unix seconds>
//! }
//! ```
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
}

impl<'a> CanonicalCommit<'a> {
    pub fn to_json(&self) -> Value {
        json!({
            "author_device": self.author_device,
            "author_pubkey": hex::encode(self.author_pubkey),
            "intent":        self.intent,
            "master_key_id": self.master_key_id,
            "parent":        self.parent.map(|h| h.to_hex()),
            "payload":       self.payload,
            "root_tree":     self.root_tree.to_hex(),
            "timestamp":     self.timestamp,
        })
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
