//! Master-key generations. Each generation has an id; new blobs use the active
//! generation, old blobs continue to decrypt under their own.

use std::collections::BTreeMap;
use std::fs;

use rand::RngCore;
use zeroize::{Zeroizing, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::kek::{unwrap_under_kek, wrap_under_kek, Kek};
use crate::params::{aad, KEY_LEN};
use crate::storage::{self, VaultPaths};

#[derive(Debug, ZeroizeOnDrop)]
pub struct MasterKey {
    #[zeroize(skip)]
    pub id: u32,
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl MasterKey {
    pub fn generate(id: u32) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            id,
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn from_bytes(id: u32, bytes: [u8; KEY_LEN]) -> Self {
        Self {
            id,
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
}

/// All master-key generations the vault holds in memory after unlock.
#[derive(Debug, Default)]
pub struct MasterKeyStore {
    keys: BTreeMap<u32, MasterKey>,
    active_id: u32,
}

impl MasterKeyStore {
    pub fn new(active_id: u32) -> Self {
        Self {
            keys: BTreeMap::new(),
            active_id,
        }
    }

    pub fn insert(&mut self, key: MasterKey) {
        self.keys.insert(key.id, key);
    }

    pub fn active_id(&self) -> u32 {
        self.active_id
    }

    pub fn set_active(&mut self, id: u32) {
        self.active_id = id;
    }

    pub fn active(&self) -> Result<&MasterKey> {
        self.keys
            .get(&self.active_id)
            .ok_or(VaultError::UnknownMasterKey(self.active_id))
    }

    pub fn get(&self, id: u32) -> Result<&MasterKey> {
        self.keys.get(&id).ok_or(VaultError::UnknownMasterKey(id))
    }

    pub fn ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.keys.keys().copied()
    }
}

pub fn write_master(paths: &VaultPaths, kek: &Kek, key: &MasterKey) -> Result<()> {
    let aad = aad::master(key.id);
    let wrapped = wrap_under_kek(kek, key.expose(), &aad);
    fs::write(paths.master(key.id), wrapped)?;
    Ok(())
}

pub fn read_master(paths: &VaultPaths, kek: &Kek, id: u32) -> Result<MasterKey> {
    let wrapped = fs::read(paths.master(id))?;
    let aad = aad::master(id);
    let plaintext = unwrap_under_kek(kek, &wrapped, &aad)?;
    if plaintext.len() != KEY_LEN {
        return Err(VaultError::Malformed("master key plaintext wrong length"));
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&plaintext);
    Ok(MasterKey::from_bytes(id, bytes))
}

pub fn read_all(paths: &VaultPaths, kek: &Kek, active_id: u32) -> Result<MasterKeyStore> {
    let mut store = MasterKeyStore::new(active_id);
    for id in storage::list_master_ids(paths)? {
        store.insert(read_master(paths, kek, id)?);
    }
    if !store.keys.contains_key(&active_id) {
        return Err(VaultError::UnknownMasterKey(active_id));
    }
    Ok(store)
}
