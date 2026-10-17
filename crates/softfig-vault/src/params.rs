use serde::{Deserialize, Serialize};

/// Bumped when the on-disk binary or TOML layout changes incompatibly.
pub const CURRENT_FORMAT_VERSION: u32 = 1;

/// Size of the salt (passed to Argon2id when deriving a passphrase-wrapping key).
pub const KEK_SALT_LEN: usize = 16;

/// Nonce size for XChaCha20-Poly1305 (24 bytes).
pub const AEAD_NONCE_LEN: usize = 24;

/// Length of K, M, and the per-blob key (256 bits).
pub const KEY_LEN: usize = 32;

/// AEAD tag length appended to ciphertext.
pub const AEAD_TAG_LEN: usize = 16;

/// AAD strings are domain separators so a ciphertext written for one purpose
/// fails to decrypt under another.
pub mod aad {
    pub const KEK_SELF: &[u8] = b"softfig.kek.self.v1";
    pub const KEK_RECOVERY: &[u8] = b"softfig.kek.recovery.v1";
    /// Growlight relock token — the third, ephemeral KEK wrapping keyed by a
    /// full-entropy 256-bit token (no Argon2). Domain-separates the relock
    /// blob from the passphrase/recovery wrappings.
    pub const KEK_RELOCK: &[u8] = b"softfig.kek.relock.v1";
    pub const IDENTITY: &[u8] = b"softfig.identity.v1";
    /// X25519 transport key — the Noise static key for softfig-net (M5a).
    pub const TRANSPORT: &[u8] = b"softfig.transport.v1";
    pub const BLOB: &[u8] = b"softfig.blob.v1";

    /// Master keys are AAD-bound to their generation id so two generations
    /// can't be swapped on disk without an integrity failure.
    pub fn master(id: u32) -> Vec<u8> {
        format!("softfig.master.v1.{id}").into_bytes()
    }
}

/// Argon2id cost parameters. Recorded on disk so a vault written on a beefy
/// machine still unlocks on a weaker one without re-deriving the cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration count.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

/// OWASP 2023 second recommendation: m=64 MiB, t=3, p=4. This is both the
/// default for a fresh vault and the **absolute floor** `vault rewrap` refuses
/// to go below without `--allow-downgrade` — one constant so the two can never
/// drift apart.
pub const OWASP_BASELINE: Argon2Params = Argon2Params {
    m_cost: 65536,
    t_cost: 3,
    p_cost: 4,
};

impl Default for Argon2Params {
    fn default() -> Self {
        OWASP_BASELINE
    }
}

impl Argon2Params {
    /// Panics on invalid costs. Callers taking operator input must
    /// [`Self::check`] first; the internal callers pass validated values.
    pub fn to_argon2(self) -> argon2::Params {
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .expect("argon2 params validated by softfig defaults")
    }

    /// Validity as Argon2 itself defines it. [`Self::to_argon2`] panics on
    /// invalid costs, and `vault rewrap` accepts numbers from an operator, so
    /// this has to run before the panic can.
    pub fn check(self) -> std::result::Result<(), String> {
        argon2::Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Memory-time area — the quantity Argon2's security argument is actually
    /// about. Widened to `u64` because `m_cost * t_cost` overflows `u32` at
    /// entirely reachable costs (64 MiB and t=3 is already 196608, and a
    /// gigabyte at t=8 is 2^23).
    pub fn area(self) -> u64 {
        u64::from(self.m_cost) * u64::from(self.t_cost)
    }

    /// Is `self` at least as strong as `other`?
    ///
    /// Two comparisons rather than one, because Argon2 cost is not totally
    /// ordered. The area may not shrink, **and** `m_cost` alone may not shrink:
    /// memory hardness is what makes GPU and ASIC attack expensive, so it must
    /// not be traded away for iterations that a parallel attacker buys cheaply.
    /// `p_cost` is deliberately excluded — it partitions the same `m x t` work
    /// across lanes rather than changing its total.
    pub fn at_least_as_strong_as(self, other: Self) -> bool {
        self.area() >= other.area() && self.m_cost >= other.m_cost
    }
}

impl std::fmt::Display for Argon2Params {
    /// `m=64 MiB t=3 p=4` — the form `vault status` and `vault rewrap` print.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "m={} t={} p={}",
            format_kib(self.m_cost),
            self.t_cost,
            self.p_cost
        )
    }
}

/// Render a KiB count the way an operator thinks about memory. Exact powers of
/// two get a MiB/GiB label; anything else stays in KiB rather than rounding a
/// security parameter into a lie.
fn format_kib(kib: u32) -> String {
    match kib {
        k if k >= 1024 * 1024 && k % (1024 * 1024) == 0 => format!("{} GiB", k / (1024 * 1024)),
        k if k >= 1024 && k % 1024 == 0 => format!("{} MiB", k / 1024),
        k => format!("{k} KiB"),
    }
}

/// Plaintext metadata at `.softfig/vault/params.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultParams {
    pub format_version: u32,
    pub argon2: Argon2Params,
}

impl Default for VaultParams {
    fn default() -> Self {
        Self {
            format_version: CURRENT_FORMAT_VERSION,
            argon2: Argon2Params::default(),
        }
    }
}

/// Plaintext pointer at `.softfig/vault/active.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveKey {
    pub master_key_id: u32,
}
