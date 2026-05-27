//! BIP39-style recovery phrase. 12 words, 128 bits of entropy + 4-bit checksum.
//!
//! `spec-vault.md` mentions "6-word BIP39-style" but 6 words yields ~66 bits,
//! which is below modern recommendations once Argon2id stretching is applied
//! to a passphrase-strength input. 12 words is the standard BIP39 entry point
//! and is what we ship. Decision logged in
//! `journal/decisions/decision-softfig-vault-impl.md`.

use crate::error::{Result, VaultError};

const WORD_COUNT: usize = 12;

/// Canonical wrapper around a BIP39 mnemonic. Use only as a one-shot token
/// at init / recovery time; never store.
#[derive(Debug)]
pub struct RecoveryPhrase {
    inner: bip39::Mnemonic,
}

impl RecoveryPhrase {
    pub fn generate() -> Self {
        let mnemonic = bip39::Mnemonic::generate(WORD_COUNT)
            .expect("12 is a valid BIP39 word count");
        Self { inner: mnemonic }
    }

    pub fn parse(phrase: &str) -> Result<Self> {
        bip39::Mnemonic::parse(phrase.trim())
            .map(|m| Self { inner: m })
            .map_err(|_| VaultError::InvalidRecoveryPhrase)
    }

    /// Canonical normalized phrase string. This is what we feed Argon2id.
    pub fn as_passphrase_bytes(&self) -> Vec<u8> {
        self.inner.to_string().into_bytes()
    }

    /// Display form (12 lowercase words, single spaces). Show once at init,
    /// strongly warn the user to store it externally, then drop.
    pub fn display(&self) -> String {
        self.inner.to_string()
    }
}
