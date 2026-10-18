//! The typed source id (spec remote-runner §4.5): the content-addressed tree a
//! job builds, plus the hash format that produced it.
//!
//! Git gives a tree object id (`git-sha1` = 20 bytes, `git-sha256` = 32); the
//! future softfig project VCS gives a BLAKE3 tree hash (32 bytes). The format
//! travels *with* the root so the runner verifies against the right hash
//! function, and so a `softfig-blake3-v1` backend can slot in behind the same
//! [`crate::SourceBackend`] without a wire change.

use std::fmt;

use crate::error::{Error, Result};

/// The source-tree hash format (spec §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceFormat {
    /// A git sha1 tree object id (20 bytes).
    GitSha1,
    /// A git sha256 tree object id (32 bytes).
    GitSha256,
    /// A softfig project-VCS BLAKE3 tree hash (32 bytes), future.
    SoftfigBlake3V1,
}

impl SourceFormat {
    /// The one-byte wire tag (field 1 of the encoded source id).
    fn tag(self) -> u8 {
        match self {
            SourceFormat::GitSha1 => 1,
            SourceFormat::GitSha256 => 2,
            SourceFormat::SoftfigBlake3V1 => 3,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(SourceFormat::GitSha1),
            2 => Some(SourceFormat::GitSha256),
            3 => Some(SourceFormat::SoftfigBlake3V1),
            _ => None,
        }
    }

    /// The root byte length this format produces.
    pub fn root_len(self) -> usize {
        match self {
            SourceFormat::GitSha1 => 20,
            SourceFormat::GitSha256 => 32,
            SourceFormat::SoftfigBlake3V1 => 32,
        }
    }

    /// The wire/display name (spec §4.5).
    pub fn as_str(self) -> &'static str {
        match self {
            SourceFormat::GitSha1 => "git-sha1",
            SourceFormat::GitSha256 => "git-sha256",
            SourceFormat::SoftfigBlake3V1 => "softfig-blake3-v1",
        }
    }

    /// Infer the format from a full hex hash's length (40 = sha1, 64 = sha256).
    fn from_hex_len(hex: &str) -> Option<Self> {
        match hex.len() {
            40 => Some(SourceFormat::GitSha1),
            64 => Some(SourceFormat::GitSha256),
            _ => None,
        }
    }
}

/// A typed source id: `{ format, root }` (spec §4.5). `root` is the raw tree
/// hash bytes, length [`SourceFormat::root_len`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SourceId {
    pub format: SourceFormat,
    pub root: Vec<u8>,
}

impl SourceId {
    /// Build a source id, checking the root length against the format.
    pub fn new(format: SourceFormat, root: Vec<u8>) -> Result<Self> {
        if root.len() != format.root_len() {
            return Err(Error::SourceId(format!(
                "{} root is {} bytes, expected {}",
                format.as_str(),
                root.len(),
                format.root_len()
            )));
        }
        Ok(Self { format, root })
    }

    /// Build a git source id from a full hex object id (inferring the format
    /// from its length — 40 chars = sha1, 64 = sha256).
    pub fn from_git_hash(hex_id: &str) -> Result<Self> {
        let hex_id = hex_id.trim();
        let format = SourceFormat::from_hex_len(hex_id).ok_or_else(|| {
            Error::SourceId(format!(
                "git object id {hex_id:?} is not 40 (sha1) or 64 (sha256) hex chars"
            ))
        })?;
        let root = hex::decode(hex_id).map_err(|e| Error::SourceId(format!("bad hex: {e}")))?;
        Self::new(format, root)
    }

    /// The canonical wire encoding carried in `JobOffer.source_id`: one format
    /// tag byte followed by the raw root. The root length is implied by the
    /// format, so the encoding is self-describing and unambiguous.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + self.root.len());
        v.push(self.format.tag());
        v.extend_from_slice(&self.root);
        v
    }

    /// Decode a wire source id. `None` on an unknown tag or a wrong-length root
    /// (never a panic — a malformed source id is a rejection, not a crash).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&tag, root) = bytes.split_first()?;
        let format = SourceFormat::from_tag(tag)?;
        if root.len() != format.root_len() {
            return None;
        }
        Some(Self {
            format,
            root: root.to_vec(),
        })
    }

    /// The root as lowercase hex (also the runner's snapshot-ref name suffix).
    pub fn hex(&self) -> String {
        hex::encode(&self.root)
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.format.as_str(), self.hex())
    }
}

impl fmt::Debug for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_sha1_round_trips() {
        let id = SourceId::from_git_hash(&"ab".repeat(20)).unwrap();
        assert_eq!(id.format, SourceFormat::GitSha1);
        assert_eq!(id.root.len(), 20);
        assert_eq!(id.hex(), "ab".repeat(20));
        assert_eq!(SourceId::decode(&id.encode()).unwrap(), id);
        assert_eq!(id.to_string(), format!("git-sha1:{}", "ab".repeat(20)));
    }

    #[test]
    fn git_sha256_round_trips() {
        let id = SourceId::from_git_hash(&"cd".repeat(32)).unwrap();
        assert_eq!(id.format, SourceFormat::GitSha256);
        assert_eq!(id.root.len(), 32);
        assert_eq!(SourceId::decode(&id.encode()).unwrap(), id);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(SourceId::from_git_hash("abcd").is_err());
        assert!(SourceId::from_git_hash(&"e".repeat(63)).is_err());
    }

    #[test]
    fn decode_rejects_unknown_tag_and_bad_length() {
        assert!(SourceId::decode(&[0x00]).is_none());
        assert!(SourceId::decode(&[0xFF; 20]).is_none());
        // tag 1 (sha1) with a 32-byte root is wrong-length.
        let mut v = vec![1u8];
        v.extend_from_slice(&[0u8; 32]);
        assert!(SourceId::decode(&v).is_none());
    }

    #[test]
    fn format_names_match_spec() {
        assert_eq!(SourceFormat::GitSha1.as_str(), "git-sha1");
        assert_eq!(SourceFormat::GitSha256.as_str(), "git-sha256");
        assert_eq!(SourceFormat::SoftfigBlake3V1.as_str(), "softfig-blake3-v1");
    }
}
