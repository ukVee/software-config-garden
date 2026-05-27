//! Public `Vault` handle: init, unlock, recover. The handle is just a path —
//! no secrets are held until `unlock` returns a `VaultSession`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Result, VaultError};
use crate::identity::{self, Identity};
use crate::kek::{self, Kek};
use crate::master::{self, MasterKey, MasterKeyStore};
use crate::params::{aad, ActiveKey, VaultParams};
use crate::recovery::RecoveryPhrase;
use crate::session::VaultSession;
use crate::storage::{self, VaultPaths};

#[derive(Debug, Clone)]
pub struct Vault {
    paths: VaultPaths,
}

impl Vault {
    /// Construct a handle from a garden root path. Does not check that a
    /// vault is actually initialized there. M1c callers use this; M2a
    /// callers (with relocated state) use [`Self::at_state_root`].
    pub fn at(garden_root: &Path) -> Self {
        Self {
            paths: VaultPaths::for_garden(garden_root),
        }
    }

    /// M2a: vault lives under a relocated state root (e.g.,
    /// `~/.local/share/softfig/<repo_id>/.softfig/vault/`).
    pub fn at_state_root(state_root: &Path) -> Self {
        Self {
            paths: VaultPaths::for_state_root(state_root),
        }
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    pub fn is_initialized(&self) -> bool {
        self.paths.exists()
    }

    /// Initialize a fresh vault: generate K, M_1, identity, return the
    /// recovery phrase exactly once. Caller must show the phrase to the
    /// user and drop it; the vault never stores it in plaintext.
    pub fn init(
        garden_root: &Path,
        passphrase: &[u8],
    ) -> Result<(Self, VaultSession, RecoveryPhrase)> {
        Self::init_with_params(garden_root, passphrase, VaultParams::default())
    }

    /// Like [`init`] but lets the caller pick non-default parameters
    /// (e.g., weaker Argon2id cost for tests, or stronger for high-threat
    /// installations).
    pub fn init_with_params(
        garden_root: &Path,
        passphrase: &[u8],
        params: VaultParams,
    ) -> Result<(Self, VaultSession, RecoveryPhrase)> {
        let paths = VaultPaths::for_garden(garden_root);
        if paths.exists() {
            return Err(VaultError::AlreadyInitialized(paths.root.clone()));
        }
        storage::ensure_dirs(&paths)?;

        storage::store_params(&paths, &params)?;

        let kek = Kek::generate();

        // Self-path passphrase wrapping.
        let wrapped_self =
            kek::wrap_kek_under_passphrase(passphrase, &kek, &params.argon2, aad::KEK_SELF);
        fs::write(paths.kek_self(), wrapped_self)?;

        // Recovery passphrase wrapping.
        let recovery = RecoveryPhrase::generate();
        let wrapped_recovery = kek::wrap_kek_under_passphrase(
            &recovery.as_passphrase_bytes(),
            &kek,
            &params.argon2,
            aad::KEK_RECOVERY,
        );
        fs::write(paths.kek_recovery(), wrapped_recovery)?;

        // First master generation + identity.
        let m1 = MasterKey::generate(1);
        master::write_master(&paths, &kek, &m1)?;
        storage::store_active(&paths, &ActiveKey { master_key_id: 1 })?;

        let identity = Identity::generate();
        identity::write_identity(&paths, &kek, &identity)?;

        let mut masters = MasterKeyStore::new(1);
        masters.insert(m1);

        let session = VaultSession {
            paths: paths.clone(),
            kek,
            masters,
            identity,
        };
        Ok((Self { paths }, session, recovery))
    }

    /// Unlock the vault using the self-path passphrase.
    pub fn unlock(&self, passphrase: &[u8]) -> Result<VaultSession> {
        self.unlock_with(passphrase, aad::KEK_SELF, &self.paths.kek_self())
    }

    /// Unlock using the recovery phrase.
    pub fn unlock_with_recovery(&self, phrase: &RecoveryPhrase) -> Result<VaultSession> {
        let bytes = phrase.as_passphrase_bytes();
        self.unlock_with(&bytes, aad::KEK_RECOVERY, &self.paths.kek_recovery())
    }

    fn unlock_with(&self, secret: &[u8], wrap_aad: &[u8], wrap_path: &PathBuf) -> Result<VaultSession> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized(self.paths.root.clone()));
        }
        let params = storage::load_params(&self.paths)?;
        let active = storage::load_active(&self.paths)?;
        let wrapped = fs::read(wrap_path)?;
        let kek = kek::unwrap_kek_under_passphrase(secret, &wrapped, &params.argon2, wrap_aad)?;
        let masters = master::read_all(&self.paths, &kek, active.master_key_id)?;
        let identity = identity::read_identity(&self.paths, &kek)?;
        Ok(VaultSession {
            paths: self.paths.clone(),
            kek,
            masters,
            identity,
        })
    }

    /// Recover from a forgotten passphrase: unlock with the recovery phrase,
    /// then re-wrap K under a new passphrase. Old `k.self` is replaced.
    pub fn recover(&self, phrase: &RecoveryPhrase, new_passphrase: &[u8]) -> Result<()> {
        let params = storage::load_params(&self.paths)?;
        let wrapped_recovery = fs::read(self.paths.kek_recovery())?;
        let kek = kek::unwrap_kek_under_passphrase(
            &phrase.as_passphrase_bytes(),
            &wrapped_recovery,
            &params.argon2,
            aad::KEK_RECOVERY,
        )?;

        let new_self =
            kek::wrap_kek_under_passphrase(new_passphrase, &kek, &params.argon2, aad::KEK_SELF);
        fs::write(self.paths.kek_self(), new_self)?;
        Ok(())
    }
}
