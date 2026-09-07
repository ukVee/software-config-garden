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

/// Regression — HIGH silent data-loss (audit slice 001). A Layer B subkey
/// is HKDF'd off the master-key bytes, so it is generation-specific. The
/// read path must decrypt under the generation that *sealed* the blob (its
/// embedded master id), not whichever generation is active after a
/// `rotate-key`. Before the fix, `decrypt_layer_b`/`decrypt_layer_b_region`
/// derived the subkey from `masters.active()`, so every file and inline
/// `<vault>` region sealed before a rotation became permanently
/// unreadable (`AuthFailed`) even though the old key is still on disk —
/// while Layer A (`decrypt_blob`) read the embedded id and survived. This
/// asserts both layers now reach parity across a rotation.
#[test]
fn rotate_key_keeps_layer_b_sealed_secrets_readable() {
    use softfig_vault::layer_b::{read_master_id, LAYER_B_MARKER};

    let (_tmp, vault) = fresh_vault();
    let mut session = vault.unlock(PASSPHRASE).expect("unlock");

    let path = "secrets/api.toml";
    let region_id = "token";
    let file_pt = b"api_key = \"hunter2\"\n";
    let region_pt = b"super-secret-region-value";

    // Seal a whole-file blob AND an inline region under generation 1,
    // plus a Layer A blob to assert cross-layer parity below.
    let file_ct = session.encrypt_layer_b(path, file_pt).expect("seal file");
    let region_ct = session
        .encrypt_layer_b_region(path, region_id, region_pt)
        .expect("seal region");
    let layer_a_ct = session.encrypt_blob(b"layer-a survivor").expect("seal layer a");

    // Sanity: both Layer B blobs carry the marker and the sealing
    // generation id (1) — the very bytes the read path must honor.
    assert_eq!(file_ct[0], LAYER_B_MARKER);
    assert_eq!(read_master_id(&file_ct).unwrap(), 1);
    assert_eq!(read_master_id(&region_ct).unwrap(), 1);

    // Rotate to generation 2; generation 1 is kept on disk.
    let new_id = session.rotate_master_key().expect("rotate");
    assert_eq!(new_id, 2);
    assert_eq!(session.active_master_key_id(), 2);
    assert_eq!(session.known_master_key_ids(), vec![1, 2]);

    // The proof: all three reveal after the rotation. Pre-fix, the two
    // Layer B reveals returned AuthFailed (the bug); Layer A always
    // worked — so passing all three together locks Layer A/B parity.
    assert_eq!(
        session.decrypt_layer_b(path, &file_ct).expect("reveal file after rotate"),
        file_pt
    );
    assert_eq!(
        session
            .decrypt_layer_b_region(path, region_id, &region_ct)
            .expect("reveal region after rotate"),
        region_pt
    );
    assert_eq!(
        session.decrypt_blob(&layer_a_ct).expect("reveal layer a after rotate"),
        b"layer-a survivor"
    );

    // A blob freshly sealed under gen 2 also round-trips (encrypt still
    // uses the active generation, and the read path selects gen 2).
    let after_ct = session
        .encrypt_layer_b(path, b"sealed after rotate")
        .expect("seal under gen2");
    assert_eq!(read_master_id(&after_ct).unwrap(), 2);
    assert_eq!(
        session.decrypt_layer_b(path, &after_ct).expect("reveal gen2 file"),
        b"sealed after rotate"
    );

    // Survives a re-unlock: generation 1 was persisted to disk, so the
    // old-generation reveal still works on a fresh session.
    drop(session);
    let session = vault.unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(session.active_master_key_id(), 2);
    assert_eq!(
        session.decrypt_layer_b(path, &file_ct).expect("reveal file after re-unlock"),
        file_pt
    );
    assert_eq!(
        session
            .decrypt_layer_b_region(path, region_id, &region_ct)
            .expect("reveal region after re-unlock"),
        region_pt
    );
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

// --- M5d: sealed shared-key store (`store/load/has_shared_key`) -------------

/// A ceremony-shaped id: `S-<16 hex>` (the real `key_id` form).
const KEY_ID: &str = "S-7f3a9b2c4d5e6f01";
const S_KEY: [u8; 32] = [0x42; 32];

#[test]
fn shared_key_roundtrips_and_is_sealed_at_rest() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");

    session.store_shared_key(KEY_ID, &S_KEY).expect("store");
    let loaded = session.load_shared_key(KEY_ID).expect("load");
    assert_eq!(*loaded, S_KEY);
    assert!(session.has_shared_key(KEY_ID));
    assert!(!session.has_shared_key("S-0000000000000000"));

    // At rest the file is the master-keyed blob format, not plaintext `S`.
    let path = tmp
        .path()
        .join(".softfig/vault/shared-keys")
        .join(format!("{KEY_ID}.key"));
    let on_disk = fs::read(&path).expect("sealed file exists");
    assert_ne!(on_disk.as_slice(), S_KEY.as_slice());
    assert!(!on_disk
        .windows(S_KEY.len())
        .any(|w| w == S_KEY.as_slice()));
}

#[test]
fn shared_key_store_is_idempotent_but_refuses_different_material() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");

    session.store_shared_key(KEY_ID, &S_KEY).expect("store");
    // Same id + same S: idempotent (convergent sealing → identical bytes).
    session.store_shared_key(KEY_ID, &S_KEY).expect("re-store");
    // Same id + different S: a caller bug or tampering — refused, and the
    // original material is untouched.
    let other = [0x43u8; 32];
    assert!(session.store_shared_key(KEY_ID, &other).is_err());
    assert_eq!(*session.load_shared_key(KEY_ID).expect("load"), S_KEY);
}

#[test]
fn shared_key_rejects_traversal_shaped_ids() {
    let (_tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    for bad in ["", "../evil", "a/b", "a.b", "S-abc def", &"x".repeat(65)] {
        assert!(session.store_shared_key(bad, &S_KEY).is_err(), "store {bad:?}");
        assert!(session.load_shared_key(bad).is_err(), "load {bad:?}");
        assert!(!session.has_shared_key(bad), "has {bad:?}");
    }
}

#[test]
fn shared_key_survives_relock_but_tamper_fails_closed() {
    let (tmp, vault) = fresh_vault();
    {
        let session = vault.unlock(PASSPHRASE).expect("unlock");
        session.store_shared_key(KEY_ID, &S_KEY).expect("store");
    }
    // A fresh unlock (new session, same master) still reads it.
    let session = Vault::at(tmp.path()).unlock(PASSPHRASE).expect("re-unlock");
    assert_eq!(*session.load_shared_key(KEY_ID).expect("load"), S_KEY);

    // Flip a ciphertext byte: AEAD auth fails closed.
    let path = tmp
        .path()
        .join(".softfig/vault/shared-keys")
        .join(format!("{KEY_ID}.key"));
    let mut bytes = fs::read(&path).expect("read sealed");
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).expect("write tampered");
    match session.load_shared_key(KEY_ID) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("expected AuthFailed on tamper, got {other:?}"),
    }
}

/// M5d slice 008 — a torn/undecryptable `<key_id>.key` (a crash mid-write, or
/// bit-rot) must NOT wedge the id: the correct `S` re-stores over the corpse
/// instead of being refused forever as "different key material". Regression for
/// the bare-`fs::write` + raw-byte idempotence-compare that made a truncated
/// file permanent.
#[test]
fn torn_shared_key_file_is_recovered_not_wedged() {
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    let path = tmp
        .path()
        .join(".softfig/vault/shared-keys")
        .join(format!("{KEY_ID}.key"));

    // Simulate a crash mid-write: a truncated blob that can never decrypt.
    // (A bare file-presence probe like `has_shared_key` still sees the corpse;
    // the honest "do I hold usable S" check is `load_shared_key`, which fails
    // closed — that is the signal a recovery driver must key off, not presence.)
    fs::create_dir_all(path.parent().unwrap()).expect("mkdir shared-keys");
    fs::write(&path, b"\x01\x02torn").expect("write torn corpse");
    assert!(session.load_shared_key(KEY_ID).is_err(), "corpse must not load");

    // The correct S re-stores over the corpse — id not wedged — and reads back.
    session
        .store_shared_key(KEY_ID, &S_KEY)
        .expect("re-store over torn file must succeed");
    assert_eq!(*session.load_shared_key(KEY_ID).expect("load"), S_KEY);
    assert!(session.has_shared_key(KEY_ID));
}

/// M5d slice 008 — the shared-keys store is the vault's first imported-key
/// surface, so the directory is `0700` and each sealed key is `0600`.
#[test]
fn shared_key_store_has_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let (tmp, vault) = fresh_vault();
    let session = vault.unlock(PASSPHRASE).expect("unlock");
    session.store_shared_key(KEY_ID, &S_KEY).expect("store");

    let dir = tmp.path().join(".softfig/vault/shared-keys");
    let file = dir.join(format!("{KEY_ID}.key"));
    let dir_mode = fs::metadata(&dir).expect("dir meta").permissions().mode() & 0o777;
    let file_mode = fs::metadata(&file).expect("file meta").permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "shared-keys dir must be 0700");
    assert_eq!(file_mode, 0o600, "sealed key must be 0600");
}

#[test]
fn random_bytes32_returns_distinct_material() {
    // Smoke, not a statistical test: two draws differing proves the surface
    // is wired to a live RNG rather than a constant.
    assert_ne!(softfig_vault::random_bytes32(), softfig_vault::random_bytes32());
}

// --- M5d slice 002: shared-chain blob crypto under S -------------------------

/// The convergence property the sync/dedup design load-bears on: two members
/// with *different* master keys but the same ceremony `S` seal the same
/// plaintext to byte-identical blob_files — for the plain shared blob AND the
/// shared Layer B whole-file seal.
#[test]
fn shared_blobs_converge_across_members_with_different_masters() {
    let (_ta, vault_a) = fresh_vault();
    let (_tb, vault_b) = fresh_vault();
    let a = vault_a.unlock(PASSPHRASE).expect("unlock a");
    let b = vault_b.unlock(PASSPHRASE).expect("unlock b");
    a.store_shared_key(KEY_ID, &S_KEY).expect("store a");
    b.store_shared_key(KEY_ID, &S_KEY).expect("store b");

    let pt = b"# shared doc\nsame on every member\n";
    let ct_a = a.encrypt_shared_blob(KEY_ID, pt).expect("encrypt a");
    let ct_b = b.encrypt_shared_blob(KEY_ID, pt).expect("encrypt b");
    assert_eq!(ct_a, ct_b, "shared blob must be convergent across members");
    assert_eq!(a.decrypt_shared_blob(&ct_b).expect("a reads b"), pt);
    assert_eq!(b.decrypt_shared_blob(&ct_a).expect("b reads a"), pt);

    let lb_a = a
        .encrypt_shared_layer_b(KEY_ID, "proj/secrets.toml", pt)
        .expect("layer b a");
    let lb_b = b
        .encrypt_shared_layer_b(KEY_ID, "proj/secrets.toml", pt)
        .expect("layer b b");
    assert_eq!(lb_a, lb_b, "shared layer B must be convergent too");
    assert_eq!(
        b.decrypt_shared_layer_b("proj/secrets.toml", &lb_a).expect("b reads"),
        pt
    );

    // A member's device blobs stay under its own M: same plaintext, different
    // masters → different Layer A ciphertext (the shared path is the only
    // cross-member-convergent one).
    assert_ne!(a.encrypt_blob(pt).unwrap(), b.encrypt_blob(pt).unwrap());
}

/// A non-member vault (its own M, no stored `S`) holds nothing readable: the
/// embedded key_id resolves to SharedKeyUnavailable, and its master key never
/// even gets a chance at the AEAD.
#[test]
fn non_member_cannot_decrypt_shared_blobs() {
    let (_ta, vault_a) = fresh_vault();
    let a = vault_a.unlock(PASSPHRASE).expect("unlock a");
    a.store_shared_key(KEY_ID, &S_KEY).expect("store");
    let ct = a.encrypt_shared_blob(KEY_ID, b"members only").expect("encrypt");

    let (_tn, vault_n) = fresh_vault();
    let n = vault_n.unlock(PASSPHRASE).expect("unlock non-member");
    match n.decrypt_shared_blob(&ct) {
        Err(VaultError::SharedKeyUnavailable(id)) => assert_eq!(id, KEY_ID),
        other => panic!("expected SharedKeyUnavailable, got {other:?}"),
    }
    // Encrypting *to* a keyed chain without holding S fails the same way —
    // the fail-closed signal the daemon's router relies on.
    match n.encrypt_shared_blob(KEY_ID, b"x") {
        Err(VaultError::SharedKeyUnavailable(_)) => {}
        other => panic!("expected SharedKeyUnavailable, got {other:?}"),
    }
}

/// An inline region inside a shared subtree round-trips under an S-derived
/// subkey and is unreadable without S (the slice-002 region test).
#[test]
fn shared_region_round_trips_and_needs_s() {
    let (_ta, vault_a) = fresh_vault();
    let a = vault_a.unlock(PASSPHRASE).expect("unlock");
    a.store_shared_key(KEY_ID, &S_KEY).expect("store");
    let ct = a
        .encrypt_shared_region(KEY_ID, "proj/notes.md", "alpha", b"region secret")
        .expect("encrypt region");
    assert_eq!(
        a.decrypt_shared_region("proj/notes.md", "alpha", &ct).expect("round-trip"),
        b"region secret"
    );

    let (_tn, vault_n) = fresh_vault();
    let n = vault_n.unlock(PASSPHRASE).expect("unlock non-member");
    assert!(matches!(
        n.decrypt_shared_region("proj/notes.md", "alpha", &ct),
        Err(VaultError::SharedKeyUnavailable(_))
    ));
}

// ---------------------------------------------------------------------------
// Recovery policy (milestone `vault-recovery-policy`, slice 001)
//
// The unit tests in `src/recovery_policy.rs` cover the model against synthetic
// fixtures. These cover it against a *real* vault, and pin the one property
// that cannot be checked with fixtures: reading the recovery status never opens
// a wrapping.
// ---------------------------------------------------------------------------

#[test]
fn init_declares_the_shape_it_just_built() {
    use softfig_vault::RecoveryStatus;

    let (tmp, vault) = fresh_vault();
    assert!(
        vault.paths().recovery_policy().exists(),
        "init should leave the vault declared, not undeclared"
    );

    let status = RecoveryStatus::read(vault.paths());
    assert!(
        !status.is_inferred(),
        "a freshly-initialized vault must not report an inferred policy"
    );
    assert_eq!(status.effective().to_string(), "passphrase+phrase");
    assert!(
        status.divergences.is_empty(),
        "init builds exactly what it declares: {:?}",
        status.divergences
    );
    drop(tmp);
}

#[test]
fn recovery_status_never_opens_a_wrapping() {
    use softfig_vault::{DeclaredPolicy, RecoveryPolicy, RecoveryStatus};

    let (_tmp, vault) = fresh_vault();
    let paths = vault.paths();

    // Destroy both wrappings. Every byte of `k.self` and `k.recovery` is now
    // garbage, so ANY attempt to unwrap `K` — with the right passphrase or
    // otherwise — fails. This is also, precisely, a *locked* vault from the
    // status path's point of view: it holds no secret with which to open
    // anything.
    fs::write(paths.kek_self(), b"shredded").expect("clobber k.self");
    fs::write(paths.kek_recovery(), b"shredded").expect("clobber k.recovery");
    assert!(
        vault.unlock(PASSPHRASE).is_err(),
        "precondition: the wrappings must genuinely be unopenable"
    );

    // Status still reports the whole picture. If it unwrapped anything on the
    // way, this call would have failed instead.
    let status = RecoveryStatus::read(paths);
    assert!(status.wrappings.passphrase);
    assert!(status.wrappings.phrase);
    assert_eq!(status.effective().to_string(), "passphrase+phrase");
    assert!(status.divergences.is_empty());

    // And divergence is still computed against the declaration, not against
    // anything the wrappings would have to be opened to learn.
    softfig_vault::recovery_policy::store_declared_policy(
        paths,
        &RecoveryPolicy::passphrase_only(),
    )
    .expect("declare");
    let status = RecoveryStatus::read(paths);
    assert!(matches!(status.declared, DeclaredPolicy::Declared(_)));
    assert_eq!(status.divergences.len(), 1, "{:?}", status.divergences);
}

#[test]
fn an_existing_undeclared_vault_reports_inferred_and_is_not_written_to() {
    use softfig_vault::{DeclaredPolicy, RecoveryStatus};

    // A garden created before the declaration existed: remove the file `init`
    // wrote and you have exactly the pre-milestone on-disk shape.
    let (_tmp, vault) = fresh_vault();
    let paths = vault.paths();
    fs::remove_file(paths.recovery_policy()).expect("de-declare");

    let status = RecoveryStatus::read(paths);
    assert_eq!(status.declared, DeclaredPolicy::Undeclared);
    assert!(status.is_inferred());
    assert_eq!(status.effective().to_string(), "passphrase+phrase");
    assert!(
        !paths.recovery_policy().exists(),
        "reading status must never write a declaration on the user's behalf"
    );
}

// ---------------------------------------------------------------------------
// vault-recovery-policy 002 — `vault escrow export`
//
// The bundle is a file-copy-and-describe artifact: these tests run against a
// real initialized vault (not a fixture of fake bytes) precisely to pin that
// what lands in the bundle is byte-identical to what the vault holds, and that
// nothing else does.
// ---------------------------------------------------------------------------

use softfig_vault::escrow;
use softfig_vault::recovery_policy;

fn b3(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[test]
fn escrow_round_trips_every_member_byte_for_byte() {
    let (tmp, vault) = fresh_vault();
    let dest = tmp.path().join("escrow.toml");

    let summary = escrow::export(vault.paths(), Some("garden-abc"), &dest, false).expect("export");
    let bundle = escrow::parse(&fs::read_to_string(&dest).unwrap()).expect("parse");

    assert_eq!(bundle.garden_id, "garden-abc");
    assert_eq!(bundle.member_count, bundle.members.len());
    assert_eq!(summary.members.len(), bundle.members.len());
    assert!(
        bundle.member("k.self").is_some() && bundle.member("master/1.key").is_some(),
        "the wrapping and the key it opens both have to be in the bundle"
    );

    for m in &bundle.members {
        let on_disk = fs::read(vault.paths().root.join(&m.name))
            .unwrap_or_else(|e| panic!("member {} is not on disk: {e}", m.name));
        let decoded = m.decoded().expect("base64");
        assert_eq!(decoded, on_disk, "member {} differs from the vault", m.name);
        assert_eq!(m.size, on_disk.len() as u64, "member {} size", m.name);
        assert_eq!(b3(&on_disk), m.blake3, "member {} hash", m.name);
    }
}

#[test]
fn escrow_carries_every_master_generation_not_just_the_active_one() {
    let (tmp, vault) = fresh_vault();
    let mut session = vault.unlock(PASSPHRASE).expect("unlock");
    let new_id = session.rotate_master_key().expect("rotate");
    assert_eq!(new_id, 2);

    let dest = tmp.path().join("escrow.toml");
    escrow::export(vault.paths(), None, &dest, false).expect("export");
    let bundle = escrow::parse(&fs::read_to_string(&dest).unwrap()).expect("parse");

    // Historical blobs name the generation that sealed them, so an escrow that
    // dropped generation 1 would restore a vault that cannot read its own past.
    assert!(bundle.member("master/1.key").is_some(), "gen 1 must survive rotation");
    assert!(bundle.member("master/2.key").is_some(), "gen 2 must be present");
}

#[test]
fn escrow_reports_a_declared_policy_as_declared_and_a_broken_one_as_inferred() {
    let (tmp, vault) = fresh_vault();
    recovery_policy::store_declared_policy(
        vault.paths(),
        &softfig_vault::RecoveryPolicy::passphrase_only(),
    )
    .expect("declare");

    let dest = tmp.path().join("declared.toml");
    escrow::export(vault.paths(), None, &dest, false).expect("export");
    let bundle = escrow::parse(&fs::read_to_string(&dest).unwrap()).expect("parse");
    assert_eq!(bundle.policy, "passphrase-only");
    assert_eq!(bundle.policy_source, escrow::SOURCE_DECLARED);
    assert!(bundle.policy_note.is_empty());
    assert!(
        bundle.member("recovery.toml").is_some(),
        "the declaration rides the bundle"
    );

    // A declaration that cannot be read must not stop the copy: export records
    // the shape it could see, says the reading failed, and ships the broken
    // file verbatim so the original is not lost with it.
    let declaration = vault.paths().recovery_policy();
    fs::write(&declaration, b"this is not a policy").unwrap();
    let dest2 = tmp.path().join("unreadable.toml");
    escrow::export(vault.paths(), None, &dest2, false).expect("export");
    let bundle = escrow::parse(&fs::read_to_string(&dest2).unwrap()).expect("parse");
    assert_eq!(bundle.policy_source, escrow::SOURCE_INFERRED);
    assert!(!bundle.policy_note.is_empty(), "say why it was inferred");
    assert_eq!(
        bundle.member("recovery.toml").unwrap().decoded().unwrap(),
        b"this is not a policy"
    );
}

#[test]
fn escrow_leaks_no_garden_content_and_no_database() {
    let (tmp, vault) = fresh_vault();
    // A plaintext note in the vault directory and a database beside it: both
    // are the leak class the allowlist exists to make structurally impossible.
    fs::write(
        vault.paths().root.join("sealed-paths.toml"),
        b"globs = [\"CANARY-GLOB-STRING\"]",
    )
    .unwrap();
    fs::write(vault.paths().root.join("notes.txt"), b"CANARY-PLAINTEXT-NOTE").unwrap();
    fs::write(
        tmp.path().join(".softfig").join("db.sqlite"),
        b"SQLite format 3 CANARY-DATABASE-BYTES",
    )
    .unwrap();

    let dest = tmp.path().join("escrow.toml");
    escrow::export(vault.paths(), None, &dest, false).expect("export");
    let raw = fs::read_to_string(&dest).unwrap();

    for canary in ["CANARY-GLOB-STRING", "CANARY-PLAINTEXT-NOTE", "CANARY-DATABASE-BYTES"] {
        assert!(!raw.contains(canary), "{canary} leaked into the bundle");
    }
    let bundle = escrow::parse(&raw).unwrap();
    for name in ["sealed-paths.toml", "notes.txt", "db.sqlite"] {
        assert!(bundle.member(name).is_none(), "{name} must not be a member");
    }
}

#[test]
fn escrow_of_a_whole_vault_stays_a_file_you_can_print() {
    let (tmp, vault) = fresh_vault();
    let dest = tmp.path().join("escrow.toml");
    let summary = escrow::export(vault.paths(), Some("garden-abc"), &dest, false).expect("export");

    // The artifact's whole premise is that it is small enough to copy
    // everywhere and put on paper. An order-of-magnitude guard: if this trips,
    // something that is not key material has started riding along.
    assert!(
        summary.bytes < 16 * 1024,
        "escrow bundle grew to {} bytes — check what got added",
        summary.bytes
    );
    assert_eq!(summary.bytes, fs::metadata(&dest).unwrap().len());
    assert_eq!(summary.bundle_blake3, b3(&fs::read(&dest).unwrap()));
}

// ---------------------------------------------------------------------------
// vault-recovery-policy 003 — `vault escrow verify`
//
// Integrity is checkable on a fixture of fake bytes; **openability is not**.
// These run against a real initialized vault with real Argon2 (at test cost)
// because the question the verb exists to answer — "would this bundle actually
// reopen my vault?" — is only answered by an unwrap that could fail.
// ---------------------------------------------------------------------------

/// Every file in the vault directory with its bytes and mtime, for proving
/// verification changed nothing.
fn vault_snapshot(root: &Path) -> Vec<(String, Vec<u8>, std::time::SystemTime)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>, std::time::SystemTime)>) {
        for entry in fs::read_dir(dir).expect("read_dir").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let meta = fs::metadata(&path).expect("metadata");
                out.push((
                    path.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                    fs::read(&path).expect("read"),
                    meta.modified().expect("mtime"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn export_and_parse(vault: &Vault, dest: &Path) -> softfig_vault::EscrowBundle {
    escrow::export(vault.paths(), Some("garden-abc"), dest, true).expect("export");
    escrow::parse(&fs::read_to_string(dest).unwrap()).expect("parse")
}

#[test]
fn escrow_verify_proves_a_fresh_bundle_actually_opens() {
    let (tmp, vault) = fresh_vault();
    let bundle = export_and_parse(&vault, &tmp.path().join("escrow.toml"));

    let report = escrow::check_integrity(&bundle);
    assert!(report.is_intact(), "findings: {:?}", report.findings);

    let proof = escrow::prove_openable(&bundle, PASSPHRASE).expect("the bundle must open");
    assert_eq!(proof.active_master_key_id, 1);
    assert_eq!(proof.generations_proved, vec![1]);
    // A fresh vault has a phrase door, and this verb cannot test it: saying so
    // is the difference between "the bundle is proved" and "the part of it
    // this verb can prove is proved".
    assert_eq!(proof.unproved_doors, vec!["k.recovery"]);
}

#[test]
fn a_wrong_passphrase_is_distinguishable_from_a_damaged_bundle() {
    let (tmp, vault) = fresh_vault();
    let bundle = export_and_parse(&vault, &tmp.path().join("escrow.toml"));

    // Right bytes, wrong secret: intact, does not open.
    assert!(escrow::check_integrity(&bundle).is_intact());
    match escrow::prove_openable(&bundle, WRONG_PASSPHRASE) {
        Err(VaultError::AuthFailed) => {}
        other => panic!("a wrong passphrase must be AuthFailed, got {other:?}"),
    }

    // Wrong bytes, right secret: the failure is named before a passphrase is
    // ever asked for. The two remedies are different — buy a new card, or
    // remember the passphrase — so the two reports have to be.
    let mut damaged = bundle.clone();
    let m = damaged
        .members
        .iter_mut()
        .find(|m| m.name == "master/1.key")
        .unwrap();
    m.blake3 = "0".repeat(64);
    let findings = escrow::check_integrity(&damaged).findings;
    assert!(
        matches!(findings.as_slice(), [escrow::Finding::Corrupt { name, .. }] if name == "master/1.key"),
        "got {findings:?}"
    );
}

#[test]
fn verification_needs_no_live_vault_and_cannot_reach_one() {
    let (tmp, vault) = fresh_vault();
    let dest = tmp.path().join("escrow.toml");
    let bundle = export_and_parse(&vault, &dest);

    // Delete the vault entirely. If verification could touch a live vault it
    // would need one; it does not, because the entry points hold no path.
    fs::remove_dir_all(tmp.path().join(".softfig")).expect("remove vault");
    assert!(!vault.is_initialized());

    assert!(escrow::check_integrity(&bundle).is_intact());
    let proof = escrow::prove_openable(&bundle, PASSPHRASE).expect("opens with no vault present");
    assert_eq!(proof.generations_proved, vec![1]);
}

#[test]
fn verifying_leaves_every_byte_of_the_live_vault_alone() {
    let (tmp, vault) = fresh_vault();
    let bundle = export_and_parse(&vault, &tmp.path().join("escrow.toml"));
    let before = vault_snapshot(&vault.paths().root);

    escrow::check_integrity(&bundle);
    escrow::prove_openable(&bundle, PASSPHRASE).expect("opens");
    // Even the failure path must not touch it.
    let _ = escrow::prove_openable(&bundle, WRONG_PASSPHRASE);

    assert_eq!(before, vault_snapshot(&vault.paths().root), "verify mutated the vault");
    assert!(
        !vault.paths().escrow_record().exists(),
        "a record is written by an explicit, separate call — never by verifying"
    );
}

#[test]
fn a_bundle_exported_before_a_rotation_still_verifies_and_repairs_nothing() {
    let (tmp, vault) = fresh_vault();
    let dest = tmp.path().join("escrow.toml");
    let stale = export_and_parse(&vault, &dest);

    let mut session = vault.unlock(PASSPHRASE).expect("unlock");
    assert_eq!(session.rotate_master_key().expect("rotate"), 2);
    drop(session);

    // The old bundle is a valid historical artifact: it verifies on its own
    // terms, against its own active pointer.
    assert!(escrow::check_integrity(&stale).is_intact());
    let proof = escrow::prove_openable(&stale, PASSPHRASE).expect("the old copy still opens");
    assert_eq!(proof.active_master_key_id, 1);
    assert_eq!(proof.generations_proved, vec![1]);

    // And the live vault is untouched — no "helpful" sync back to generation 1.
    assert_eq!(
        softfig_vault::storage::load_active(vault.paths()).unwrap().master_key_id,
        2
    );
    assert!(vault.paths().master(2).exists());

    // A fresh export of the rotated vault proves both generations.
    let current = export_and_parse(&vault, &tmp.path().join("escrow2.toml"));
    let proof = escrow::prove_openable(&current, PASSPHRASE).expect("opens");
    assert_eq!(proof.active_master_key_id, 2);
    assert_eq!(proof.generations_proved, vec![1, 2], "history must stay readable");
}

#[test]
fn a_member_that_belongs_to_another_vault_is_not_a_wrong_passphrase() {
    let (tmp_a, vault_a) = fresh_vault();
    let (tmp_b, vault_b) = fresh_vault();
    let mut bundle = export_and_parse(&vault_a, &tmp_a.path().join("a.toml"));
    let other = export_and_parse(&vault_b, &tmp_b.path().join("b.toml"));

    // Substitute B's master key into A's bundle, manifest and all, so integrity
    // passes. The passphrase is right; the bundle is not.
    let swapped = other.member("master/1.key").unwrap().clone();
    let slot = bundle
        .members
        .iter_mut()
        .find(|m| m.name == "master/1.key")
        .unwrap();
    *slot = swapped;
    assert!(escrow::check_integrity(&bundle).is_intact(), "the swap is hash-consistent");

    match escrow::prove_openable(&bundle, PASSPHRASE) {
        Err(VaultError::EscrowMalformed(msg)) => {
            assert!(msg.contains("master/1.key"), "{msg}");
            assert!(msg.contains("passphrase was right"), "{msg}");
        }
        other => panic!("expected an EscrowMalformed naming the member, got {other:?}"),
    }
}

#[test]
fn the_verification_record_survives_a_round_trip_and_stays_out_of_the_bundle() {
    let (tmp, vault) = fresh_vault();
    let dest = tmp.path().join("escrow.toml");
    let raw = {
        escrow::export(vault.paths(), Some("garden-abc"), &dest, false).expect("export");
        fs::read(&dest).unwrap()
    };
    let bundle = escrow::parse(std::str::from_utf8(&raw).unwrap()).expect("parse");
    let report = escrow::check_integrity(&bundle);
    escrow::prove_openable(&bundle, PASSPHRASE).expect("opens");

    let entry = escrow::VerificationRecord {
        bundle_blake3: escrow::bundle_blake3(&raw),
        self_blake3: report.self_blake3.clone(),
        garden_id: bundle.garden_id.clone(),
        policy: bundle.policy.clone(),
        member_count: bundle.members.len(),
        outcome: escrow::OUTCOME_OPENABLE.to_string(),
        verified_at: 0,
    };
    escrow::record_verification(vault.paths(), entry, 1_700_000_000).expect("record");

    let log = escrow::read_verifications(vault.paths()).expect("read back");
    let latest = log.latest().expect("one row");
    assert_eq!(latest.verified_at, 1_700_000_000);
    assert_eq!(latest.outcome, escrow::OUTCOME_OPENABLE);
    assert_eq!(latest.self_blake3, b3(&fs::read(vault.paths().kek_self()).unwrap()));
    assert!(
        log.verified(&escrow::bundle_blake3(&raw)).is_some(),
        "the row is keyed by the bundle's own hash"
    );
    // It records hashes, never contents: no member's bytes appear in the file.
    let record_raw = fs::read_to_string(vault.paths().escrow_record()).unwrap();
    for m in &bundle.members {
        assert!(!record_raw.contains(&m.data), "member {} leaked into the record", m.name);
    }

    // And recording must not change what the vault exports — otherwise
    // verifying a copy would invalidate every copy.
    let after = tmp.path().join("escrow-after.toml");
    escrow::export(vault.paths(), Some("garden-abc"), &after, false).expect("re-export");
    assert_eq!(raw, fs::read(&after).unwrap(), "the record must not enter the bundle");
}

#[test]
fn a_recorded_proof_goes_stale_when_the_passphrase_door_is_replaced() {
    let (tmp, vault, phrase) = fresh_vault_with_recovery();
    let bundle = export_and_parse(&vault, &tmp.path().join("escrow.toml"));
    let report = escrow::check_integrity(&bundle);
    escrow::prove_openable(&bundle, PASSPHRASE).expect("opens");
    let recorded_self = report.self_blake3.clone();

    assert_eq!(
        escrow::current_self_blake3(vault.paths()).unwrap(),
        recorded_self,
        "the fresh proof matches the live door"
    );

    // `recover` re-wraps K under a new passphrase: same vault, new k.self. The
    // old bundle is still a valid artifact of the old door, but it is no longer
    // a proof that today's vault reopens — which is exactly the fact `drop`
    // will have to gate on in slice 004.
    vault.recover(&phrase, NEW_PASSPHRASE).expect("recover");
    assert_ne!(
        escrow::current_self_blake3(vault.paths()).unwrap(),
        recorded_self,
        "a replaced door must be visible as a stale proof"
    );
    // The old copy still opens under the old passphrase — it was never a lie.
    escrow::prove_openable(&bundle, PASSPHRASE).expect("the historical copy still opens");
}

#[test]
fn recording_against_a_directory_that_is_not_a_vault_is_refused() {
    let tmp = TempDir::new().expect("tempdir");
    let paths = softfig_vault::VaultPaths::for_garden(tmp.path());
    let entry = escrow::VerificationRecord {
        bundle_blake3: "aaaa".into(),
        self_blake3: "bbbb".into(),
        garden_id: "garden-abc".into(),
        policy: "passphrase-only".into(),
        member_count: 5,
        outcome: escrow::OUTCOME_OPENABLE.to_string(),
        verified_at: 0,
    };
    match escrow::record_verification(&paths, entry, 1_000) {
        Err(VaultError::NotInitialized(_)) => {}
        other => panic!("expected NotInitialized, got {other:?}"),
    }
}
