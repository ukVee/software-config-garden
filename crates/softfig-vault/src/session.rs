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
    pub fn decrypt_layer_b(&self, path: &str, blob_file: &[u8]) -> Result<Vec<u8>> {
        let m = self.masters.active()?;
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
    /// derived for `(path, id)`.
    pub fn decrypt_layer_b_region(
        &self,
        path: &str,
        id: &str,
        blob_file: &[u8],
    ) -> Result<Vec<u8>> {
        let m = self.masters.active()?;
        let key = layer_b::derive_region_subkey(m, path, id);
        layer_b::decrypt(blob_file, &key)
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
