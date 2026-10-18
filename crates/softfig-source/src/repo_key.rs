//! The repo key (spec remote-runner §4.3): a BLAKE3 fingerprint of the source
//! repo's genesis, stable across clones, worktrees and renames.

/// Domain-separation prefix for the repo key.
pub const REPO_KEY_DOMAIN: &[u8] = b"softfig/runner/repo/v1";

/// Compute the repo key for a requester + repo:
/// `BLAKE3(REPO_KEY_DOMAIN ‖ requester_device_id ‖ sorted root-commit ids)`.
///
/// Root commit ids are the genesis the mirror is keyed on, so a repo cloned or
/// moved elsewhere still lands on the same mirror. Each root is length-prefixed
/// (a repo is one object format, so roots share a length, but prefixing keeps
/// the domain unambiguous even if that ever changes). The device id is folded
/// in so two requesters never share a mirror or a cache.
pub fn repo_key(device_id: &[u8; 32], root_commits: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REPO_KEY_DOMAIN);
    hasher.update(device_id);

    let mut roots: Vec<&[u8]> = root_commits.iter().map(Vec::as_slice).collect();
    roots.sort_unstable();
    for root in roots {
        hasher.update(&(root.len() as u32).to_be_bytes());
        hasher.update(root);
    }

    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: u8) -> [u8; 32] {
        [id; 32]
    }

    #[test]
    fn is_stable_and_sorted() {
        let a = vec![vec![0x01u8; 20], vec![0x02u8; 20]];
        let b = vec![vec![0x02u8; 20], vec![0x01u8; 20]];
        // Root order must not matter (they are sorted before hashing).
        assert_eq!(repo_key(&device(7), &a), repo_key(&device(7), &b));
    }

    #[test]
    fn device_id_is_folded_in() {
        let roots = vec![vec![0x01u8; 20]];
        assert_ne!(repo_key(&device(1), &roots), repo_key(&device(2), &roots));
    }

    #[test]
    fn roots_are_folded_in() {
        assert_ne!(
            repo_key(&device(1), &[vec![0x01u8; 20]]),
            repo_key(&device(1), &[vec![0x02u8; 20]])
        );
    }

    #[test]
    fn output_is_32_bytes() {
        assert_eq!(repo_key(&device(1), &[]).len(), 32);
    }
}
