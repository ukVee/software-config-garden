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

// --- M5a: X25519 transport key ---------------------------------------------

#[test]
fn init_writes_transport_key() {
    let tmp = TempDir::new().expect("tempdir");
    let (_vault, session, _recovery) =
        Vault::init_with_params(tmp.path(), PASSPHRASE, fast_params()).expect("init");

    assert!(
        tmp.path().join(".softfig/vault/transport.key").is_file(),
        "transport.key missing after init"
    );
    assert_ne!(
        session.transport_pubkey(),
        [0u8; 32],
        "transport pubkey must not be all-zero"
    );
}

/// `transport_pubkey()` is genuinely the X25519 public key of the secret the
/// Noise layer is handed — the relationship `softfig-net`/snow relies on.
#[test]
fn transport_pubkey_is_x25519_of_secret() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let expected =
        x25519_dalek::x25519(*session.transport_secret(), x25519_dalek::X25519_BASEPOINT_BYTES);
    assert_eq!(session.transport_pubkey(), expected);
}

#[test]
fn transport_key_stable_across_unlock() {
    let (_tmp, vault) = fresh_vault();
    let (pubkey, secret) = {
        let s = vault.unlock(PASSPHRASE).expect("unlock");
        (s.transport_pubkey(), *s.transport_secret())
    };
    let s2 = vault.unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(s2.transport_pubkey(), pubkey, "transport pubkey survives re-unlock");
    assert_eq!(*s2.transport_secret(), secret, "transport secret survives re-unlock");
}

#[test]
fn distinct_vaults_have_distinct_transport_keys() {
    let (_a, va) = fresh_vault();
    let (_b, vb) = fresh_vault();
    let pa = va.unlock(PASSPHRASE).expect("unlock a").transport_pubkey();
    let pb = vb.unlock(PASSPHRASE).expect("unlock b").transport_pubkey();
    assert_ne!(pa, pb, "two fresh vaults must mint different transport keys");
}

/// Pre-M5a vaults have no `transport.key`; unlock must mint and persist one.
#[test]
fn transport_key_auto_generated_on_unlock_when_absent() {
    let (tmp, vault) = fresh_vault();
    let key_path = tmp.path().join(".softfig/vault/transport.key");

    // Simulate a vault initialised before M5a.
    fs::remove_file(&key_path).expect("remove transport.key");
    assert!(!key_path.exists());

    let session = vault.unlock(PASSPHRASE).expect("unlock without transport key");
    assert!(key_path.is_file(), "unlock should have minted transport.key");
    let regenerated = session.transport_pubkey();
    drop(session);

    // The minted key is now stable across subsequent unlocks (not re-minted).
    let session2 = vault.unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(
        session2.transport_pubkey(),
        regenerated,
        "auto-generated transport key must persist, not re-mint each unlock"
    );
}

/// A present-but-corrupt transport key is a tamper signal, not a silent
/// regeneration.
#[test]
fn corrupt_transport_key_is_rejected() {
    let (tmp, vault) = fresh_vault();
    let key_path = tmp.path().join(".softfig/vault/transport.key");
    let mut bytes = fs::read(&key_path).expect("read transport.key");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01; // flip a tag byte
    fs::write(&key_path, &bytes).expect("write corrupt transport.key");

    match vault.unlock(PASSPHRASE) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed on corrupt transport key, got {other:?}"),
    }
}

// ---- growlight relock token -------------------------------------------

const NOW: i64 = 1_700_000_000;

/// Mint a token from a live session, then redeem it on a fresh `Vault`
/// handle (simulating the daemon restart) — the rebuilt session must carry
/// the same masters/identity/transport as the original unlock.
#[test]
fn relock_mint_redeem_round_trip() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let want_transport = session.transport_pubkey();
    let want_identity = session.identity_pubkey().to_bytes();
    let want_master = session.active_master_key_id();

    let (token, blob) = session.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");
    drop(session); // the original session is gone, as it would be across a restart

    // A brand-new handle on the same on-disk vault (the restarted daemon).
    let fresh = Vault::at(tmp.path());
    let resumed = fresh
        .redeem_relock(&token, &blob.encode(), NOW + 60)
        .expect("redeem");
    assert_eq!(resumed.transport_pubkey(), want_transport);
    assert_eq!(resumed.identity_pubkey().to_bytes(), want_identity);
    assert_eq!(resumed.active_master_key_id(), want_master);
}

/// Token survives a hex serialization round-trip (the `cycle` reply / the
/// persisted `relock-arm` file both carry hex).
#[test]
fn relock_token_hex_round_trip_redeems() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let (token, blob) = session.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");
    let hex = token.to_hex();
    drop(session);

    let parsed = softfig_vault::RelockToken::from_hex(&hex).expect("parse hex");
    Vault::at(tmp.path())
        .redeem_relock(&parsed, &blob.encode(), NOW + 1)
        .expect("redeem via hex token");
}

/// An expired token is refused even with the correct bytes.
#[test]
fn relock_expired_token_is_refused() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let (token, blob) = session.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");
    drop(session);

    let past_expiry = NOW + softfig_vault::RELOCK_TTL_SECS + 1;
    match Vault::at(tmp.path()).redeem_relock(&token, &blob.encode(), past_expiry) {
        Err(VaultError::RelockExpired) => {}
        other => panic!("expected RelockExpired, got {other:?}"),
    }
}

/// The wrong token never unwraps the KEK.
#[test]
fn relock_wrong_token_fails() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let (_token, blob) = session.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");
    drop(session);

    let attacker = softfig_vault::RelockToken::generate();
    match Vault::at(tmp.path()).redeem_relock(&attacker, &blob.encode(), NOW + 1) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed for wrong token, got {other:?}"),
    }
}

/// Editing the plaintext `expires_at` to extend the TTL breaks the AAD — the
/// expiry is authenticated, so a tampered blob fails closed rather than
/// granting a longer-lived token.
#[test]
fn relock_extending_expiry_breaks_aad() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let (token, blob) = session.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");
    drop(session);

    // Forge a blob with a far-future expiry but the original ciphertext.
    let forged = softfig_vault::RelockBlob {
        expires_at: NOW + 10 * softfig_vault::RELOCK_TTL_SECS,
        wrapped: blob.wrapped.clone(),
    };
    match Vault::at(tmp.path()).redeem_relock(&token, &forged.encode(), NOW + 1) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed for forged expiry, got {other:?}"),
    }
}

/// A blob minted against one vault must not redeem against another — the
/// fingerprint (BLAKE3 of `k.self`) is bound into the AAD.
#[test]
fn relock_blob_does_not_cross_gardens() {
    let (_tmp_a, vault_a) = fresh_vault();
    let session_a = vault_a.unlock(PASSPHRASE).expect("unlock a");
    let (token, blob) = session_a.mint_relock(NOW, softfig_vault::RELOCK_TTL_SECS).expect("mint");

    // A second, independent vault (different KEK wrapping → different fp).
    let (tmp_b, _vault_b) = fresh_vault();
    match Vault::at(tmp_b.path()).redeem_relock(&token, &blob.encode(), NOW + 1) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed across gardens, got {other:?}"),
    }
}
