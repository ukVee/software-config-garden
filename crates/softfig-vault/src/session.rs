//! In-memory unlocked state. Drop = K, M-store, identity zeroed.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::blob;
use crate::error::Result;
use crate::identity::Identity;
use crate::kek::Kek;
use crate::layer_b::{self, LayerBKey};
use crate::master::MasterKeyStore;
use crate::storage::VaultPaths;
use crate::transport::TransportKey;

#[derive(Debug)]
pub struct VaultSession {
    pub(crate) paths: VaultPaths,
    pub(crate) kek: Kek,
    pub(crate) masters: MasterKeyStore,
    pub(crate) identity: Identity,
    pub(crate) transport: TransportKey,
}

impl VaultSession {
    pub fn active_master_key_id(&self) -> u32 {
        self.masters.active_id()
    }

    pub fn known_master_key_ids(&self) -> Vec<u32> {
        self.masters.ids().collect()
    }

    pub fn encrypt_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        blob::encrypt_blob(&self.masters, plaintext)
    }

    pub fn decrypt_blob(&self, blob_file: &[u8]) -> Result<Vec<u8>> {
        blob::decrypt_blob(&self.masters, blob_file)
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.identity.sign(msg)
    }

    /// Derive a per-file Layer B subkey for `path` (repo-relative
    /// string). The subkey is HKDF'd off the active master key with the
    /// path as salt; never persisted. See [`crate::layer_b`].
    pub fn derive_layer_b_subkey(&self, path: &str) -> Result<LayerBKey> {
        let m = self.masters.active()?;
        Ok(layer_b::derive_subkey(m, path.as_bytes()))
    }

    /// Encrypt `plaintext` under a Layer B subkey for `path`. Output is
    /// a complete content-addressable blob_file with the Layer B marker.
    pub fn encrypt_layer_b(&self, path: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let m = self.masters.active()?;
        let key = layer_b::derive_subkey(m, path.as_bytes());
        layer_b::encrypt(m.id, plaintext, &key)
    }

    /// Decrypt a Layer B blob_file using the subkey derived for `path`.
    ///
    /// The subkey is HKDF'd off the master-key bytes, so it is
    /// generation-specific: the blob must be decrypted under the
    /// generation that *sealed* it, not whichever is active now. That id
    /// is embedded in the blob ([`layer_b::read_master_id`]), so a file
    /// sealed before a [`Self::rotate_master_key`] still reveals
    /// afterwards — mirroring Layer A's [`crate::blob::decrypt_blob`].
    /// (Encrypt stays on `active()`: new seals use the current
    /// generation.)
    pub fn decrypt_layer_b(&self, path: &str, blob_file: &[u8]) -> Result<Vec<u8>> {
        let id = layer_b::read_master_id(blob_file)?;
        let m = self.masters.get(id)?;
        let key = layer_b::derive_subkey(m, path.as_bytes());
        layer_b::decrypt(blob_file, &key)
    }

    /// Derive the per-region Layer B subkey for `(path, id)`. M2c inline
    /// `<vault>` tags route through this; never persisted.
    pub fn derive_layer_b_region_subkey(&self, path: &str, id: &str) -> Result<LayerBKey> {
        let m = self.masters.active()?;
        Ok(layer_b::derive_region_subkey(m, path, id))
    }

    /// Encrypt `plaintext` under a per-region Layer B subkey for
    /// `(path, id)`. Output is a complete content-addressable blob_file
    /// with the Layer B marker — the M2c on-write code base64-encodes
    /// this and embeds the result as the `<vault id="...">…</vault>`
    /// body.
    pub fn encrypt_layer_b_region(
        &self,
        path: &str,
        id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let m = self.masters.active()?;
        let key = layer_b::derive_region_subkey(m, path, id);
        layer_b::encrypt(m.id, plaintext, &key)
    }

    /// Decrypt an inline-`<vault>`-region blob_file under the subkey
    /// derived for `(path, id)`. Like [`Self::decrypt_layer_b`], the
    /// subkey is derived from the generation that *sealed* the region
    /// (the embedded master id), so inline regions also survive a
    /// [`Self::rotate_master_key`].
    pub fn decrypt_layer_b_region(
        &self,
        path: &str,
        id: &str,
        blob_file: &[u8],
    ) -> Result<Vec<u8>> {
        let gen_id = layer_b::read_master_id(blob_file)?;
        let m = self.masters.get(gen_id)?;
        let key = layer_b::derive_region_subkey(m, path, id);
        layer_b::decrypt(blob_file, &key)
    }

    /// M5d — persist an externally-derived 32-byte shared-subtree key `S`
    /// under the vault, addressable by its public `key_id` (`S-<hex>`). The
    /// key is sealed with the master-keyed blob format
    /// ([`crate::blob::encrypt_blob`]) at
    /// `.softfig/vault/shared-keys/<key_id>.key`, so it is readable only
    /// through an unlocked session — the same at-rest posture as every other
    /// vault secret. `S` is full-entropy ceremony output, so the convergent
    /// nonce derivation is safe here and makes the write idempotent (same
    /// `S` + same master → identical sealed bytes).
    ///
    /// Storing a *different* `S` under an already-used `key_id` is refused:
    /// `key_id` is a one-way hash of `S`, so a mismatch means a caller bug or
    /// tampering, never a legitimate rotation (rotation derives a fresh
    /// `key_id`).
    pub fn store_shared_key(&self, key_id: &str, s: &[u8; 32]) -> Result<()> {
        validate_shared_key_id(key_id)?;
        let sealed = blob::encrypt_blob(&self.masters, s)?;
        let path = self.paths.shared_key(key_id);
        if let Ok(existing) = std::fs::read(&path) {
            if existing == sealed {
                return Ok(()); // idempotent re-store
            }
            return Err(crate::error::VaultError::Malformed(
                "shared key id already stored with different key material",
            ));
        }
        std::fs::create_dir_all(self.paths.shared_keys_dir())?;
        std::fs::write(&path, &sealed)?;
        Ok(())
    }

    /// M5d — fetch a stored shared-subtree key by its `key_id`. Zeroized on
    /// drop; the caller must not copy it out of the returned guard except
    /// into another zeroizing home. A key this vault never stored surfaces
    /// as [`VaultError::SharedKeyUnavailable`] — the non-member /
    /// pre-ceremony signal, distinct from a decrypt failure.
    pub fn load_shared_key(&self, key_id: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        validate_shared_key_id(key_id)?;
        let path = self.paths.shared_key(key_id);
        let sealed = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                crate::error::VaultError::SharedKeyUnavailable(key_id.to_string())
            } else {
                e.into()
            }
        })?;
        let plain = zeroize::Zeroizing::new(blob::decrypt_blob(&self.masters, &sealed)?);
        let s: [u8; 32] = plain.as_slice().try_into().map_err(|_| {
            crate::error::VaultError::Malformed("shared key blob is not 32 bytes")
        })?;
        Ok(zeroize::Zeroizing::new(s))
    }

    /// M5d — whether a shared key is already stored under `key_id`. An
    /// invalid id is simply "not stored".
    pub fn has_shared_key(&self, key_id: &str) -> bool {
        validate_shared_key_id(key_id).is_ok() && self.paths.shared_key(key_id).is_file()
    }

    /// M5d slice 002 — encrypt a shared-chain blob under the stored `S` for
    /// `key_id` ([`crate::shared`] container, spec-convergent: every member
    /// produces identical bytes). Fails with
    /// [`VaultError::SharedKeyUnavailable`](crate::error::VaultError) when
    /// this vault holds no such `S` — the caller must fail closed, never
    /// fall back to `M` for a keyed chain.
    pub fn encrypt_shared_blob(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let s = self.load_shared_key(key_id)?;
        crate::shared::encrypt_blob(key_id, &s, plaintext)
    }

    /// M5d slice 002 — decrypt either shared container (`0xFE` blob or
    /// `0xFD` Layer B whole-file seal) by resolving its embedded `key_id`
    /// through the shared-key store. Chain-agnostic: the blob names the `S`
    /// generation that sealed it, so reads (and post-rotation history) need
    /// no chain context.
    pub fn decrypt_shared_blob(&self, blob_file: &[u8]) -> Result<Vec<u8>> {
        let key_id = crate::shared::read_key_id(blob_file)?;
        let s = self.load_shared_key(&key_id)?;
        crate::shared::decrypt_blob(&s, blob_file)
    }

    /// M5d slice 002 — whole-file Layer B seal *inside* a shared subtree:
    /// the per-file subkey derives from that chain's `S`, not `M`
    /// (`spec-vault.md`), so the seal stays members-only.
    pub fn encrypt_shared_layer_b(
        &self,
        key_id: &str,
        path: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let s = self.load_shared_key(key_id)?;
        crate::shared::encrypt_layer_b(key_id, &s, path, plaintext)
    }

    /// M5d slice 002 — decrypt a shared Layer B whole-file seal under the
    /// subkey derived from its embedded `key_id`'s `S` + `path`.
    pub fn decrypt_shared_layer_b(&self, path: &str, blob_file: &[u8]) -> Result<Vec<u8>> {
        let key_id = crate::shared::read_key_id(blob_file)?;
        let s = self.load_shared_key(&key_id)?;
        crate::shared::decrypt_layer_b(&s, path, blob_file)
    }

    /// M5d slice 002 — inline `<vault>` region seal inside a shared subtree
    /// (per-region subkey from `S`; the keeperd write-path wiring is gated
    /// on shared-chain `PriorTipGuard` coverage, but the crypto surface is
    /// complete).
    pub fn encrypt_shared_region(
        &self,
        key_id: &str,
        path: &str,
        id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let s = self.load_shared_key(key_id)?;
        crate::shared::encrypt_region(key_id, &s, path, id, plaintext)
    }

    /// M5d slice 002 — decrypt an inline shared region.
    pub fn decrypt_shared_region(
        &self,
        path: &str,
        id: &str,
        blob_file: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = crate::shared::read_key_id(blob_file)?;
        let s = self.load_shared_key(&key_id)?;
        crate::shared::decrypt_region(&s, path, id, blob_file)
    }

    /// Test whether `passphrase` unlocks this session's self-path KEK.
    /// Used by the daemon to verify a fresh master-password prompt
    /// before allowing a `softfig reveal`. Argon2id cost is paid on
    /// every call — that's by design for the reveal flow.
    pub fn verify_master_passphrase(&self, passphrase: &[u8]) -> Result<()> {
        use crate::kek::unwrap_kek_under_passphrase;
        use crate::params::aad;
        use crate::storage;
        let params = storage::load_params(&self.paths)?;
        let wrapped = std::fs::read(self.paths.kek_self())?;
        let _kek = unwrap_kek_under_passphrase(
            passphrase,
            &wrapped,
            &params.argon2,
            aad::KEK_SELF,
        )?;
        Ok(())
    }

    pub fn identity_pubkey(&self) -> VerifyingKey {
        self.identity.pubkey()
    }

    /// This device's X25519 transport public key (the Noise static pubkey).
    /// Exchanged in the Noise handshake; persisted in a peer's ring (M5a-2).
    pub fn transport_pubkey(&self) -> [u8; 32] {
        self.transport.pubkey()
    }

    /// This device's raw X25519 transport secret, for establishing Noise
    /// sessions in `softfig-net`. Zeroized when the session drops (lock).
    pub fn transport_secret(&self) -> &[u8; 32] {
        self.transport.secret_bytes()
    }

    /// Growlight relock: mint a one-time token and wrap the live KEK under it,
    /// so an unattended daemon restart can rebuild this session without the
    /// passphrase. Returns `(token, blob)`: the caller hands `token` to the
    /// `cycle` process (RAM) or persists it (`relock-arm`), and writes `blob`
    /// to tmpfs. The token expires at `now + ttl_secs` (unix seconds), bound
    /// into the blob's AAD so it cannot be tampered longer. See
    /// [`crate::relock`].
    pub fn mint_relock(
        &self,
        now: i64,
        ttl_secs: i64,
    ) -> Result<(crate::relock::RelockToken, crate::relock::RelockBlob)> {
        let expires_at = now + ttl_secs;
        let fingerprint = crate::relock::vault_fingerprint(&self.paths)?;
        let aad = crate::relock::relock_aad(&fingerprint, expires_at);
        let token = crate::relock::RelockToken::generate();
        let wrapped = crate::kek::wrap_kek_under_token(token.expose(), &self.kek, &aad);
        Ok((
            token,
            crate::relock::RelockBlob {
                expires_at,
                wrapped,
            },
        ))
    }

    /// Generate a new master key generation, persist it under K, set it
    /// active. Existing generations are kept on disk so historical blobs
    /// continue to decrypt.
    pub fn rotate_master_key(&mut self) -> Result<u32> {
        let new_id = self.masters.ids().max().unwrap_or(0) + 1;
        let key = crate::master::MasterKey::generate(new_id);
        crate::master::write_master(&self.paths, &self.kek, &key)?;
        self.masters.insert(key);
        self.masters.set_active(new_id);
        crate::storage::store_active(
            &self.paths,
            &crate::params::ActiveKey {
                master_key_id: new_id,
            },
        )?;
        Ok(new_id)
    }
}

/// A shared-key id is used as a filename under `.softfig/vault/shared-keys/`,
/// so it must never traverse: non-empty, ≤ 64 bytes, and only
/// `[A-Za-z0-9_-]` (the real ids are `S-<hex>`, well inside this). No dots,
/// no separators.
fn validate_shared_key_id(key_id: &str) -> Result<()> {
    let ok = !key_id.is_empty()
        && key_id.len() <= 64
        && key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(crate::error::VaultError::Malformed(
            "shared key id must be 1-64 chars of [A-Za-z0-9_-]",
        ))
    }
}
