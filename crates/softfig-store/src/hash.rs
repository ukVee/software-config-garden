//! 32-byte BLAKE3 content-address. We carry it as a fixed-size newtype so
//! callers can't accidentally mix lengths, but it serializes as a hex string
//! when it lands in JCS payloads or sqlite TEXT columns.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::StoreError;

pub const HASH_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; HASH_LEN]);

impl Hash {
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, StoreError> {
        let v = hex::decode(s).map_err(|_| StoreError::BadHashHex(s.to_string()))?;
        if v.len() != HASH_LEN {
            return Err(StoreError::BadHashHex(s.to_string()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&v);
        Ok(Self(out))
    }

    pub fn of(content: &[u8]) -> Self {
        Self(*blake3::hash(content).as_bytes())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Hash {
    type Err = StoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Hash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
