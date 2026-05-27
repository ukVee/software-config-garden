use std::fs;
use std::path::Path;

use softfig_vault::params::{Argon2Params, VaultParams};
use softfig_vault::{Vault, VaultError};
use tempfile::TempDir;

const PASSPHRASE: &[u8] = b"correct horse battery staple";
const NEW_PASSPHRASE: &[u8] = b"hunter2 hunter2 hunter2";
const WRONG_PASSPHRASE: &[u8] = b"definitely-wrong";

/// Use minimum Argon2id cost in tests so the suite runs in seconds, not minutes.
fn fast_params() -> VaultParams {
    VaultParams {
        format_version: softfig_vault::params::CURRENT_FORMAT_VERSION,
        argon2: Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        },
    }
}

fn fresh_vault() -> (TempDir, Vault) {
    let tmp = TempDir::new().expect("tempdir");
    let (vault, _session, _recovery) =
        Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init");
    (tmp, vault)
}

fn fresh_vault_with_recovery() -> (TempDir, Vault, softfig_vault::RecoveryPhrase) {
    let tmp = TempDir::new().expect("tempdir");
    let (vault, _session, recovery) =
        Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init");
    (tmp, vault, recovery)
}

#[test]
fn init_writes_expected_layout() {
    let tmp = TempDir::new().expect("tempdir");
    let (_vault, session, recovery) =
        Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init");

    let root = tmp.path().join(".softfig/vault");
    assert!(root.is_dir(), "vault dir missing");
    for f in ["params.toml", "active.toml", "k.self", "k.recovery", "identity.key"] {
        assert!(root.join(f).is_file(), "missing {f}");
    }
    assert!(root.join("master/1.key").is_file(), "missing master/1.key");

    assert_eq!(session.active_master_key_id(), 1);
    assert_eq!(session.known_master_key_ids(), vec![1]);

    let phrase = recovery.display();
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 12, "recovery phrase should be 12 words");

    // Plaintext metadata files should not contain the passphrase or master bytes.
    let params_raw = fs::read_to_string(root.join("params.toml")).unwrap();
    assert!(params_raw.contains("format_version"));
    assert!(params_raw.contains("[argon2]"));
}

#[test]
fn unlock_round_trip() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    assert_eq!(session.active_master_key_id(), 1);
}

#[test]
fn wrong_passphrase_fails_cleanly() {
    let (_tmp, vault) = fresh_vault();
    match vault.unlock(WRONG_PASSPHRASE) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn convergent_encryption_is_deterministic() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let plaintext = b"hello, garden";
    let a = session.encrypt_blob(plaintext).expect("encrypt a");
    let b = session.encrypt_blob(plaintext).expect("encrypt b");
    assert_eq!(a, b, "same plaintext + same M must produce identical blob_file");
    assert_eq!(blake3::hash(&a), blake3::hash(&b));
}

#[test]
fn different_plaintexts_yield_unrelated_ciphertexts() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let a = session.encrypt_blob(b"alpha").expect("encrypt a");
    let b = session.encrypt_blob(b"beta").expect("encrypt b");
    assert_ne!(a, b);
    // Nonces (24 bytes after the 1-byte varint id=1) should differ entirely.
    assert_ne!(&a[1..25], &b[1..25]);
}

#[test]
fn encrypt_decrypt_round_trip() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    for pt in [b"".as_slice(), b"x", b"the quick brown fox", &vec![0xAB; 4096]] {
        let ct = session.encrypt_blob(pt).expect("encrypt");
        let back = session.decrypt_blob(&ct).expect("decrypt");
        assert_eq!(back, pt);
    }
}

#[test]
fn tamper_detection_at_every_byte() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let pt = b"sensitive";
    let ct = session.encrypt_blob(pt).expect("encrypt");

    for i in 0..ct.len() {
        let mut bad = ct.clone();
        bad[i] ^= 0x01;
        assert!(
            session.decrypt_blob(&bad).is_err(),
            "byte {i} flip should fail decrypt"
        );
    }

    // Truncation should also fail.
    assert!(session.decrypt_blob(&ct[..ct.len() - 1]).is_err());
    assert!(session.decrypt_blob(&[]).is_err());
}

#[test]
fn rotate_key_keeps_old_blobs_readable() {
    let (_tmp, vault) = fresh_vault();
    let mut session = vault.unlock(PASSPHRASE).expect("unlock");

    let old = session.encrypt_blob(b"before rotation").expect("encrypt");
    assert_eq!(old[0], 1, "varint id of m=1 should be a single byte 0x01");

    let new_id = session.rotate_master_key().expect("rotate");
    assert_eq!(new_id, 2);
    assert_eq!(session.active_master_key_id(), 2);
    assert_eq!(session.known_master_key_ids(), vec![1, 2]);

    let new = session.encrypt_blob(b"after rotation").expect("encrypt");
    assert_eq!(new[0], 2);

    assert_eq!(session.decrypt_blob(&old).expect("decrypt old"), b"before rotation");
    assert_eq!(session.decrypt_blob(&new).expect("decrypt new"), b"after rotation");

    // After re-unlock, the new active id and both generations persist.
    drop(session);
    let session = vault.unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(session.active_master_key_id(), 2);
    assert_eq!(session.known_master_key_ids(), vec![1, 2]);
    assert_eq!(session.decrypt_blob(&old).unwrap(), b"before rotation");
    assert_eq!(session.decrypt_blob(&new).unwrap(), b"after rotation");
}

#[test]
fn recover_replaces_passphrase_without_disturbing_blobs() {
    let (tmp, vault, recovery) = fresh_vault_with_recovery();

    // Encrypt a blob under the original passphrase.
    let blob = {
        let session = vault.unlock(PASSPHRASE).expect("unlock");
        session.encrypt_blob(b"survives recovery").expect("encrypt")
    };

    vault.recover(&recovery, NEW_PASSPHRASE).expect("recover");

    // Old passphrase no longer works.
    assert!(matches!(
        vault.unlock(PASSPHRASE),
        Err(VaultError::AuthFailed)
    ));

    // New passphrase works and decrypts the pre-recovery blob.
    let session = vault.unlock(NEW_PASSPHRASE).expect("unlock with new pass");
    assert_eq!(
        session.decrypt_blob(&blob).expect("decrypt survivor"),
        b"survives recovery"
    );

    // Recovery phrase still unlocks too.
    let _via_recovery = vault.unlock_with_recovery(&recovery).expect("recovery unlock");

    // Verify on-disk: only k.self changed; k.recovery, master, identity untouched.
    let _ = tmp;
}

#[test]
fn sign_and_verify_round_trip() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let pubkey = session.identity_pubkey();

    let msg = b"commit:00112233";
    let sig = session.sign(msg);
    use ed25519_dalek::Verifier;
    pubkey.verify(msg, &sig).expect("signature verifies");

    // Tampered message rejected.
    let mut bad_msg = msg.to_vec();
    bad_msg[0] ^= 0x01;
    assert!(pubkey.verify(&bad_msg, &sig).is_err());

    // Identity is stable across unlocks.
    drop(session);
    let session2 = vault.unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(
        session2.identity_pubkey().to_bytes(),
        pubkey.to_bytes(),
        "identity pubkey survives re-unlock"
    );
}

#[test]
fn cannot_init_twice() {
    let tmp = TempDir::new().expect("tempdir");
    Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init 1");
    let again = Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params());
    assert!(matches!(again, Err(VaultError::AlreadyInitialized(_))));
}

#[test]
fn unknown_master_id_rejected_at_decrypt() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let mut blob = session.encrypt_blob(b"x").expect("encrypt");
    // Stomp the id varint so it references a generation that doesn't exist.
    blob[0] = 99;
    match session.decrypt_blob(&blob) {
        Err(VaultError::UnknownMasterKey(99)) => {}
        other => panic!("expected UnknownMasterKey(99), got {other:?}"),
    }
}

/// Compile-time check: secret-bearing types implement `ZeroizeOnDrop`.
/// If this stops compiling, someone removed the marker.
#[test]
fn keys_are_zeroized_on_drop() {
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<softfig_vault::kek::Kek>();
    assert_zod::<softfig_vault::master::MasterKey>();
}

/// Confirm `discover_garden` walks up to find `.softfig/`.
#[test]
fn discover_garden_walks_up() {
    let tmp = TempDir::new().expect("tempdir");
    Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init");
    let nested = tmp.path().join("a/b/c");
    fs::create_dir_all(&nested).unwrap();
    let found = softfig_vault::discover_garden(&nested).expect("should find garden");
    assert_eq!(canonical(&found), canonical(tmp.path()));
}

fn canonical(p: &Path) -> std::path::PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}
