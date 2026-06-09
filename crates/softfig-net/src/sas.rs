//! The Short Authentication String (SAS) that defeats a pairing MITM.
//!
//! # Why it works
//!
//! Noise `XX` gives a confidential, integrity-protected channel and proves each
//! side holds *some* X25519 static — but on first contact neither side knows
//! the other's key in advance, so a man-in-the-middle can sit between them,
//! running one `XX` session with each victim using its *own* static. Both
//! victims get a perfectly valid encrypted channel; they are just talking to
//! the attacker.
//!
//! The defence is the Noise handshake hash `h`: it commits to the entire
//! transcript, including both static keys. Two honest endpoints derive an
//! *identical* `h`; the two legs of a MITM derive *different* `h` (each commits
//! to the attacker's key on one side). The [`Sas`] is a short code derived from
//! `h` and shown on both devices. The user compares them on an
//! already-trusted device; a mismatch means a MITM and the pairing is aborted.
//!
//! # Derivation (exact)
//!
//! ```text
//! okm  = HKDF-SHA256(salt = SAS_HKDF_SALT, ikm = h, info = SAS_HKDF_INFO, L = 8)
//! code = be_u64(okm) mod 10^6
//! ```
//!
//! `h` is the 32-byte Noise `XX` handshake hash
//! ([`NoiseSession::handshake_hash`](crate::transport::NoiseSession::handshake_hash);
//! BLAKE2s). The salt and info strings are versioned constants for domain
//! separation. The result is rendered as **six decimal digits**.
//!
//! # Encoding choice: six decimal digits
//!
//! Numeric digits over a word list: locale-independent, trivial to read aloud
//! or type on the headless server, and no wordlist dependency to vendor and
//! keep in sync across implementations of the future public program. Six digits
//! (~20 bits) matches the Bluetooth "numeric comparison" convention. An active
//! MITM must make *both* legs' codes collide; truncating an HKDF output to 10^6
//! values gives a per-attempt collision probability of 1/10^6, and the attempt
//! is online and one-shot (a mismatch aborts the pairing), which is the
//! standard SAS security argument. Raising the digit count later is a versioned
//! change to `SAS_HKDF_INFO`.

use hkdf::Hkdf;
use sha2::Sha256;

/// Domain-separation salt for the SAS HKDF (versioned).
const SAS_HKDF_SALT: &[u8] = b"softfig/pairing/sas/salt/v1";
/// Domain-separation info string for the SAS HKDF (versioned; bump alongside
/// any change to [`SAS_DIGITS`]).
const SAS_HKDF_INFO: &[u8] = b"softfig/pairing/sas/numeric/v1";

/// Number of decimal digits in the SAS short code.
pub const SAS_DIGITS: usize = 6;

/// 10^[`SAS_DIGITS`] — the code modulus.
const SAS_MODULUS: u64 = 1_000_000;

/// A pairing short code derived from the Noise handshake hash. Compare across
/// the two devices; equal ⇒ no MITM, unequal ⇒ abort.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas(u32);

impl Sas {
    /// Derive the SAS from a Noise `XX` handshake hash. Deterministic: both
    /// honest endpoints feed in the same `h` and get the same code.
    pub fn from_handshake_hash(handshake_hash: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SAS_HKDF_SALT), handshake_hash);
        let mut okm = [0u8; 8];
        hk.expand(SAS_HKDF_INFO, &mut okm)
            .expect("8 bytes is well within HKDF-SHA256's 255*32 output ceiling");
        Sas((u64::from_be_bytes(okm) % SAS_MODULUS) as u32)
    }

    /// The raw numeric code (`0..10^SAS_DIGITS`).
    pub fn code(self) -> u32 {
        self.0
    }

    /// The zero-padded digit string, e.g. `"007421"`.
    pub fn digits(self) -> String {
        format!("{:0width$}", self.0, width = SAS_DIGITS)
    }

    /// The digit string grouped `XXX XXX` for legible display / read-aloud.
    pub fn grouped(self) -> String {
        let d = self.digits();
        format!("{} {}", &d[..3], &d[3..])
    }
}

impl std::fmt::Display for Sas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.grouped())
    }
}

impl std::fmt::Debug for Sas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sas({})", self.grouped())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_hash() {
        let h = [42u8; 32];
        assert_eq!(Sas::from_handshake_hash(&h), Sas::from_handshake_hash(&h));
    }

    #[test]
    fn differs_for_different_hash() {
        // A single-bit transcript difference (the MITM case) must change the
        // code with overwhelming probability.
        let mut h2 = [42u8; 32];
        h2[0] ^= 0x01;
        assert_ne!(
            Sas::from_handshake_hash(&[42u8; 32]).code(),
            Sas::from_handshake_hash(&h2).code()
        );
    }

    #[test]
    fn renders_six_digits() {
        let s = Sas::from_handshake_hash(&[7u8; 32]);
        assert_eq!(s.digits().len(), SAS_DIGITS);
        assert!(s.digits().chars().all(|c| c.is_ascii_digit()));
        assert!(s.code() < SAS_MODULUS as u32);
        // "XXX XXX" grouping is the six digits plus one space.
        assert_eq!(s.grouped().len(), SAS_DIGITS + 1);
    }
}
