//! Relock token — a third, ephemeral KEK wrapping (growlight).
//!
//! Lets an unattended daemon restart resume an **already-unlocked** vault
//! without the human's passphrase. The live KEK is wrapped under a 256-bit
//! random token `T` (full-entropy → no Argon2; see [`crate::kek`]) and the
//! resulting blob lives on tmpfs with a short, AAD-authenticated TTL. The
//! token never touches the durable `.softfig/vault/` tree.
//!
//! - Mint ([`VaultSession::mint_relock`]) generates `T`, wraps the KEK, and
//!   returns `(T, blob)`. The daemon writes `blob` to `$XDG_RUNTIME_DIR`.
//! - Redeem ([`Vault::redeem_relock`]) verifies the expiry, recomputes the
//!   vault fingerprint, unwraps the KEK with `T`, and rebuilds the session
//!   exactly as `unlock` does.
//!
//! Design: `journal/decisions/decision-softfig-relock-token.md`; crypto
//! detail: `meta/spec-vault.md` "Relock token — a third KEK wrapping".

use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::params::aad;
use crate::params::KEY_LEN;
use crate::storage::VaultPaths;

/// Token length: 256 bits, matching the KEK.
pub const RELOCK_TOKEN_LEN: usize = KEY_LEN;

/// Default time-to-live for a minted token, in seconds (20 minutes). The
/// expiry is authenticated by the blob's AAD, so it cannot be edited longer.
pub const RELOCK_TTL_SECS: i64 = 20 * 60;

/// Magic prefix of the on-tmpfs relock blob; bumped if the layout changes.
const RELOCK_MAGIC: &[u8; 4] = b"SFR1";

/// A one-time relock token `T`. Zeroized on drop. Mint returns it to the
/// daemon, which either hands it back to the `cycle` CLI process (held in RAM)
/// or persists it to a second `0600` tmpfs file for `relock-arm`/`relock`.
#[derive(Clone)]
pub struct RelockToken(Zeroizing<[u8; RELOCK_TOKEN_LEN]>);

impl std::fmt::Debug for RelockToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bytes.
        f.write_str("RelockToken(<redacted>)")
    }
}

impl RelockToken {
    /// Generate a fresh full-entropy token.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; RELOCK_TOKEN_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    pub fn from_bytes(bytes: [u8; RELOCK_TOKEN_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Parse a lowercase/uppercase hex token (64 hex chars).
    pub fn from_hex(s: &str) -> Result<Self> {
        let raw = hex::decode(s.trim())
            .map_err(|_| VaultError::RelockMalformed("token is not valid hex"))?;
        let bytes: [u8; RELOCK_TOKEN_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::RelockMalformed("token wrong length"))?;
        Ok(Self::from_bytes(bytes))
    }

    /// Lowercase hex encoding, for the `cycle` reply / persisted token file.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_ref())
    }

    pub fn expose(&self) -> &[u8; RELOCK_TOKEN_LEN] {
        &self.0
    }
}

/// The on-tmpfs relock artifact. `expires_at` is stored in the clear so the
/// daemon can pre-check the TTL (and surface it in `status`) without the
/// token — but it is *also* bound into the AEAD AAD, so editing the file to
/// extend it breaks the tag and the unwrap fails closed.
#[derive(Debug, Clone)]
pub struct RelockBlob {
    /// Unix seconds at which this token expires.
    pub expires_at: i64,
    /// KEK wrapped under the token (`nonce || ciphertext+tag`).
    pub wrapped: Vec<u8>,
}

impl RelockBlob {
    /// Serialize: `magic(4) || expires_at_be(8) || wrapped`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 8 + self.wrapped.len());
        out.extend_from_slice(RELOCK_MAGIC);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&self.wrapped);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 + 8 {
            return Err(VaultError::RelockMalformed("blob too short"));
        }
        if &bytes[..4] != RELOCK_MAGIC {
            return Err(VaultError::RelockMalformed("bad magic"));
        }
        let expires_at = i64::from_be_bytes(bytes[4..12].try_into().unwrap());
        Ok(Self {
            expires_at,
            wrapped: bytes[12..].to_vec(),
        })
    }
}

/// A stable, plaintext-derivable identifier for this vault, used to
/// cross-garden-bind a relock blob: `BLAKE3(k.self bytes)`. Available at both
/// mint and redeem **without** unlocking, since `k.self` is the (encrypted)
/// passphrase-wrapped KEK that already sits on disk. A vault whose passphrase
/// wrapping is rewritten (e.g. `recover()`) gets a new fingerprint, which
/// correctly invalidates any outstanding relock blob.
pub fn vault_fingerprint(paths: &VaultPaths) -> Result<[u8; 32]> {
    let self_blob = std::fs::read(paths.kek_self())?;
    Ok(*blake3::hash(&self_blob).as_bytes())
}

/// Build the AEAD AAD: `KEK_RELOCK ‖ fingerprint ‖ expires_at_be`.
pub(crate) fn relock_aad(fingerprint: &[u8; 32], expires_at: i64) -> Vec<u8> {
    let mut aad_bytes = Vec::with_capacity(aad::KEK_RELOCK.len() + 32 + 8);
    aad_bytes.extend_from_slice(aad::KEK_RELOCK);
    aad_bytes.extend_from_slice(fingerprint);
    aad_bytes.extend_from_slice(&expires_at.to_be_bytes());
    aad_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hex_round_trip() {
        let t = RelockToken::generate();
        let hex = t.to_hex();
        assert_eq!(hex.len(), 64);
        let back = RelockToken::from_hex(&hex).unwrap();
        assert_eq!(back.expose(), t.expose());
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = RelockToken::generate();
        assert_eq!(format!("{t:?}"), "RelockToken(<redacted>)");
    }

    #[test]
    fn from_hex_rejects_garbage() {
        assert!(RelockToken::from_hex("nothex").is_err());
        assert!(RelockToken::from_hex("ab").is_err());
    }

    #[test]
    fn blob_round_trip() {
        let blob = RelockBlob {
            expires_at: 1_700_000_000,
            wrapped: vec![1, 2, 3, 4, 5],
        };
        let back = RelockBlob::decode(&blob.encode()).unwrap();
        assert_eq!(back.expires_at, blob.expires_at);
        assert_eq!(back.wrapped, blob.wrapped);
    }

    #[test]
    fn blob_decode_rejects_bad_magic() {
        let mut bytes = RelockBlob {
            expires_at: 1,
            wrapped: vec![9],
        }
        .encode();
        bytes[0] = b'X';
        assert!(matches!(
            RelockBlob::decode(&bytes),
            Err(VaultError::RelockMalformed(_))
        ));
    }
}
