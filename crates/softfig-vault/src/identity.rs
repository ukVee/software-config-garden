//! The device's Ed25519 identity keypair. Used by the future VCS layer to sign
//! commits. Private scalar is stored on disk wrapped under K.

use std::fs;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::kek::{unwrap_under_kek, wrap_under_kek, Kek};
use crate::params::aad;
use crate::storage::VaultPaths;

#[derive(Debug)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn pubkey(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.signing.sign(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        self.signing.verifying_key().verify(msg, sig).is_ok()
    }

    fn secret_bytes(&self) -> Zeroizing<[u8; SECRET_KEY_LENGTH]> {
        Zeroizing::new(self.signing.to_bytes())
    }
}

pub fn write_identity(paths: &VaultPaths, kek: &Kek, identity: &Identity) -> Result<()> {
    let secret = identity.secret_bytes();
    let wrapped = wrap_under_kek(kek, secret.as_ref(), aad::IDENTITY);
    fs::write(paths.identity(), wrapped)?;
    Ok(())
}

pub fn read_identity(paths: &VaultPaths, kek: &Kek) -> Result<Identity> {
    let wrapped = fs::read(paths.identity())?;
    let plaintext = unwrap_under_kek(kek, &wrapped, aad::IDENTITY)?;
    if plaintext.len() != SECRET_KEY_LENGTH {
        return Err(VaultError::Malformed("identity secret wrong length"));
    }
    let mut bytes = [0u8; SECRET_KEY_LENGTH];
    bytes.copy_from_slice(&plaintext);
    Ok(Identity::from_secret_bytes(bytes))
}
