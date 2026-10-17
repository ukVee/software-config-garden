//! `vault rewrap` — re-derive `k.self` under heavier Argon2 parameters.
//!
//! In a passphrase-only posture the KDF cost is the *entire* brute-force
//! defence of the garden, so this is the compensating knob for choosing a
//! single wrapping. It is also the cheapest security upgrade in the codebase:
//! it rewrites about a hundred bytes. `M` is untouched, every blob is
//! untouched, every commit hash is untouched, and no replica resyncs —
//! precisely because the KEK indirection exists so the passphrase can change
//! without re-encrypting data.
//!
//! # One file, by construction
//!
//! A rewrap writes **exactly one file**: `k.self`. It does not update
//! `params.toml`, and that is load-bearing rather than lazy. Since slice 005
//! the costs live inside the wrapping (see [`crate::kek`]), so `params.toml`'s
//! `argon2` table is now the fallback for **v1 blobs still on disk** — and
//! `rewrap` cannot rewrite `k.recovery`, because opening it needs the phrase,
//! which may be lost, which is the premise of this whole milestone. Rewriting
//! `params.toml` with the new heavy costs would therefore make a surviving
//! `k.recovery` unopenable: the same torn-vault outcome the embedding was
//! introduced to delete, reached by a different road.
//!
//! With one write there is no ordering to get wrong, and
//! [`crate::wrappings::write_wrapping`] makes that write crash-atomic. A crash
//! leaves the old `k.self` or the new one, never a torn one.
//!
//! # Two consequences that must be announced, not discovered
//!
//! - [`crate::relock::vault_fingerprint`] hashes `k.self` alone, so a rewrap
//!   invalidates every outstanding relock blob. Discovering that at the next
//!   `softfig daemon cycle` is the worst possible moment to discover it.
//! - [`crate::escrow`] proofs are bound to a `k.self` hash, so a rewrap turns a
//!   current proof into a historical one — and `vault recovery drop` refuses
//!   without a current proof. Rehardening therefore costs a fresh
//!   export-and-verify.

use crate::error::{Result, VaultError};
use crate::escrow;
use crate::kek::{self, WrappingParams};
use crate::params::{aad, Argon2Params, OWASP_BASELINE};
use crate::recovery_policy::{RecoveryPath, Wrappings};
use crate::storage::{self, VaultPaths};
use crate::wrappings;

/// The most memory `calibrate` will ask for: 1 GiB. Past this the unlock
/// latency and the resident-memory spike stop being a good trade on the class
/// of machine soft-fig targets, and an operator who genuinely wants more can
/// say so explicitly with `--m-cost`.
pub const MAX_CALIBRATED_M_COST: u32 = 1024 * 1024;

/// What a rewrap would do, evaluated before any passphrase is typed.
///
/// Same shape as slice 004's [`crate::DropPlan`] and for the same reason: the
/// guards are cheap, the consequences are not obvious, and a refusal should
/// never cost a passphrase prompt.
#[derive(Debug, Clone)]
pub struct RewrapPlan {
    /// The parameters `k.self` opens under today, and whether it carries them.
    pub current: WrappingParams,
    /// The parameters it will be rewritten under.
    pub target: Argon2Params,
    /// True when the operator also asked to change the passphrase.
    pub changes_passphrase: bool,
    /// Doors that will still be v1 afterwards, and so still depend on
    /// `params.toml` for their costs. Naming them is how the operator learns
    /// that a rehardened vault still has a door at the old cost.
    pub legacy_doors: Vec<RecoveryPath>,
    /// True when a *current* escrow proof exists that this rewrap will turn
    /// into a historical one.
    pub invalidates_escrow_proof: bool,
    /// True when the target is weaker than the floor or than the current
    /// parameters, and `--allow-downgrade` was given to permit it.
    pub is_downgrade: bool,
}

impl RewrapPlan {
    /// Nothing to do: same costs, same passphrase. Rewrapping anyway is legal
    /// (it re-randomizes the salt), but the caller should be able to say so.
    pub fn is_noop(&self) -> bool {
        self.current.embedded && self.current.params == self.target && !self.changes_passphrase
    }
}

/// Evaluate the plan. Reads `k.self`'s header and the vault's metadata; opens
/// nothing and asks for nothing.
pub fn plan(paths: &VaultPaths, target: Argon2Params, allow_downgrade: bool) -> Result<RewrapPlan> {
    if !paths.exists() {
        return Err(VaultError::NotInitialized(paths.root.clone()));
    }
    target
        .check()
        .map_err(|e| VaultError::InvalidArgon2Params(format!("{target}: {e}")))?;

    let current = wrappings::self_wrapping_params(paths)?;

    // Two bounds, each checked the same way: never below the published
    // baseline, and never below what this vault already has. The second is the
    // one that makes `rewrap` unable to quietly weaken a hardened vault.
    let below_floor = !target.at_least_as_strong_as(OWASP_BASELINE);
    let below_current = !target.at_least_as_strong_as(current.params);
    let is_downgrade = below_floor || below_current;
    if is_downgrade && !allow_downgrade {
        return Err(VaultError::WeakerParams {
            target: target.to_string(),
            floor: if below_current {
                current.params.to_string()
            } else {
                OWASP_BASELINE.to_string()
            },
            what: if below_current {
                "this vault's current parameters"
            } else {
                "the recommended baseline"
            },
        });
    }

    Ok(RewrapPlan {
        current,
        target,
        changes_passphrase: false,
        legacy_doors: legacy_doors(paths),
        invalidates_escrow_proof: escrow::current_proof(paths)?.record.is_some(),
        is_downgrade,
    })
}

/// Doors other than `k.self` that are still in the pre-embedding format, and so
/// still read their costs from `params.toml`.
fn legacy_doors(paths: &VaultPaths) -> Vec<RecoveryPath> {
    let wrappings = Wrappings::read(paths);
    let mut out = Vec::new();
    if wrappings.contains(RecoveryPath::Phrase)
        && let Ok(bytes) = std::fs::read(paths.kek_recovery()) {
            // `params.toml` is the fallback either way; only `embedded` is
            // being asked about here, so the fallback value is irrelevant.
            if !kek::wrapping_params(&bytes, &OWASP_BASELINE).embedded {
                out.push(RecoveryPath::Phrase);
            }
        }
    out
}

/// Perform the rewrap: unwrap `K` under the current passphrase, re-wrap it
/// under `plan.target` (and `new_passphrase`, if given), and publish `k.self`.
///
/// The plan's guards are re-evaluated here rather than trusted from the caller,
/// mirroring slice 004: a plan shown to a user and a plan acted on are separated
/// by a passphrase prompt, and nothing may change in between without being
/// re-checked.
pub fn apply(
    paths: &VaultPaths,
    plan: &RewrapPlan,
    passphrase: &[u8],
    new_passphrase: Option<&[u8]>,
) -> Result<()> {
    let fresh = self::plan(paths, plan.target, plan.is_downgrade)?;
    if fresh.current.params != plan.current.params || fresh.current.embedded != plan.current.embedded
    {
        return Err(VaultError::Malformed(
            "k.self changed between planning and applying the rewrap",
        ));
    }

    let fallback = storage::load_params(paths)?.argon2;
    let wrapped = std::fs::read(paths.kek_self())?;
    let kek = kek::unwrap_kek_under_passphrase(passphrase, &wrapped, &fallback, aad::KEK_SELF)?;

    let secret = new_passphrase.unwrap_or(passphrase);
    let rewrapped = kek::wrap_kek_under_passphrase(secret, &kek, &plan.target, aad::KEK_SELF)?;

    // Prove the new wrapping opens BEFORE it replaces the one that does.
    //
    // This is the milestone's own standard applied to its most dangerous write:
    // an untested backup is not a backup, and an unverified `k.self` is not a
    // door. Checking in memory rather than after the write is what makes it a
    // guarantee instead of a rollback path — if this fails, the vault has not
    // been touched at all, so there is no window and nothing to undo. It costs
    // one extra derivation at the new cost, which is the price of never
    // publishing bytes nobody has opened.
    let proof = kek::unwrap_kek_under_passphrase(secret, &rewrapped, &plan.target, aad::KEK_SELF)?;
    if proof.expose() != kek.expose() {
        return Err(VaultError::Malformed(
            "the rewrapped k.self did not reproduce K — refusing to publish it",
        ));
    }

    // One file, one atomic publish. The declared policy is untouched: a rewrap
    // changes the secret and the cost behind a door, it does not add or remove
    // one — the same reasoning `Vault::recover` records.
    wrappings::write_wrapping(&paths.kek_self(), &rewrapped)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// A measured parameter choice.
#[derive(Debug, Clone, Copy)]
pub struct Calibration {
    pub params: Argon2Params,
    /// How long the final probe's derivation actually took.
    pub measured_ms: u64,
    /// How many derivations were run to get here.
    pub probes: u32,
    /// True when the search hit [`MAX_CALIBRATED_M_COST`] or the floor rather
    /// than the target latency. The caller should say so: "1 GiB, 2.4 s" is a
    /// different statement from "1 GiB, as requested".
    pub clamped: bool,
}

/// Choose `m_cost` so that unlocking takes roughly `target_ms` on *this*
/// machine, holding `t_cost` and `p_cost` fixed.
///
/// The same approach `systemd-cryptenroll` and `cryptsetup` take, and for the
/// same reason: the right cost is a property of the hardware, not a number in a
/// document. Argon2's runtime is very nearly linear in `m_cost`, so each probe
/// scales the previous estimate by `target / measured` and re-measures; three
/// refinements are more than enough to land inside a factor the timing noise
/// swamps anyway.
///
/// Never returns anything below [`OWASP_BASELINE`] — a fast machine does not
/// license a weak vault — and never above [`MAX_CALIBRATED_M_COST`].
pub fn calibrate(target_ms: u64, t_cost: u32, p_cost: u32) -> Result<Calibration> {
    let mut params = Argon2Params {
        m_cost: OWASP_BASELINE.m_cost,
        t_cost,
        p_cost,
    };
    params
        .check()
        .map_err(|e| VaultError::InvalidArgon2Params(format!("{params}: {e}")))?;

    let mut measured = probe_ms(&params);
    let mut probes = 1;
    for _ in 0..3 {
        let next = next_m_cost(params.m_cost, measured, target_ms);
        if next == params.m_cost {
            break;
        }
        params.m_cost = next;
        measured = probe_ms(&params);
        probes += 1;
    }

    let clamped = params.m_cost == OWASP_BASELINE.m_cost || params.m_cost == MAX_CALIBRATED_M_COST;
    Ok(Calibration {
        params,
        measured_ms: measured,
        probes,
        clamped,
    })
}

/// One step of the linear rescale, pure so the clamping is testable without
/// paying for an Argon2 derivation.
///
/// Rounds down to a whole MiB: `m_cost` is reported to a human, and
/// "m=131072 KiB" reads as noise where "m=128 MiB" reads as a decision. The
/// rounding can only reduce the cost within one MiB, which the floor clamp then
/// catches.
fn next_m_cost(current_m: u32, measured_ms: u64, target_ms: u64) -> u32 {
    if measured_ms == 0 {
        // Too fast to time. Jump rather than divide by zero; the next probe
        // will measure something.
        return (u64::from(current_m) * 8).min(u64::from(MAX_CALIBRATED_M_COST)) as u32;
    }
    let scaled = u64::from(current_m).saturating_mul(target_ms) / measured_ms;
    let whole_mib = (scaled / 1024) * 1024;
    whole_mib.clamp(
        u64::from(OWASP_BASELINE.m_cost),
        u64::from(MAX_CALIBRATED_M_COST),
    ) as u32
}

/// Time one real derivation at these costs. A throwaway passphrase and salt:
/// Argon2's runtime does not depend on their contents, only on the costs.
fn probe_ms(params: &Argon2Params) -> u64 {
    use std::time::Instant;
    let salt = [0u8; crate::params::KEK_SALT_LEN];
    let started = Instant::now();
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.to_argon2(),
    );
    let mut out = zeroize::Zeroizing::new([0u8; crate::params::KEY_LEN]);
    let _ = argon.hash_password_into(b"softfig-calibration-probe", &salt, out.as_mut());
    started.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::VaultParams;
    use crate::recovery::RecoveryPhrase;

    const TEST_PASSPHRASE: &[u8] = b"correct horse battery staple";


    #[test]
    fn the_rescale_is_linear_between_the_bounds() {
        // 128 MiB measured at 500 ms, targeting 1000 ms -> 256 MiB.
        assert_eq!(next_m_cost(131072, 500, 1000), 262144);
        // Halving the target halves the memory.
        assert_eq!(next_m_cost(262144, 1000, 500), 131072);
    }

    #[test]
    fn the_rescale_never_returns_less_than_the_baseline() {
        // A machine so slow that the target implies 8 MiB still gets the floor:
        // hardware speed does not license a weak vault.
        assert_eq!(next_m_cost(65536, 8000, 1000), OWASP_BASELINE.m_cost);
    }

    #[test]
    fn the_rescale_never_returns_more_than_the_cap() {
        assert_eq!(next_m_cost(1024 * 1024, 1, 100_000), MAX_CALIBRATED_M_COST);
    }

    #[test]
    fn an_unmeasurably_fast_probe_jumps_rather_than_dividing_by_zero() {
        assert_eq!(next_m_cost(65536, 0, 1000), 65536 * 8);
        assert_eq!(next_m_cost(MAX_CALIBRATED_M_COST, 0, 1000), MAX_CALIBRATED_M_COST);
    }

    #[test]
    fn the_rescale_rounds_down_to_a_whole_mebibyte() {
        // 100000 KiB scaled x1 rounds to 98 MiB, not a number nobody can read.
        assert_eq!(next_m_cost(100_000, 1000, 1000) % 1024, 0);
    }

    #[test]
    fn calibration_returns_valid_parameters_at_or_above_the_floor() {
        // A target this small clamps at the floor on any machine, which keeps
        // the test to a single 64 MiB derivation. The band itself is asserted
        // in the integration suite, where the clamp escape hatch is explicit —
        // a wall-clock assertion on a loaded machine is a flake, not a test.
        let c = calibrate(1, 3, 4).expect("calibration runs");
        assert!(c.params.check().is_ok());
        assert!(c.params.at_least_as_strong_as(OWASP_BASELINE));
        assert!(c.params.m_cost <= MAX_CALIBRATED_M_COST);
        assert_eq!(c.params.m_cost, OWASP_BASELINE.m_cost);
        assert!(c.clamped, "a 1 ms target must report itself clamped");
        assert!(c.probes >= 1);
    }

    // -----------------------------------------------------------------------
    // Interoperation with the pre-embedding format.
    //
    // These live here rather than in `tests/integration.rs` because writing a
    // genuine v1 blob is deliberately crate-private: nothing in production
    // writes that format any more, and the only honest way to test reading one
    // is to produce a real one rather than a hand-rolled fixture that drifts
    // away from what is actually on disk.
    // -----------------------------------------------------------------------

    #[test]
    fn a_v1_phrase_door_still_opens_after_the_self_door_is_rewrapped() {
        // THE torn-write regression, in its post-embedding form. Before this
        // slice, `k.self` and `params.toml` had to agree, so rehardening either
        // rewrote `params.toml` (breaking `k.recovery`, which cannot be
        // re-derived without the phrase) or left it stale (breaking `k.self`).
        // With the costs embedded there is no second file to move, so both
        // doors keep working across a rewrap at completely different costs.
        let (tmp, vault) = vault_with_v1_doors();
        let paths = vault.paths().clone();
        let params_before = std::fs::read(paths.params()).unwrap();

        let target = Argon2Params {
            m_cost: 64,
            t_cost: 3,
            p_cost: 1,
        };
        let plan = plan(&paths, target, true).expect("plan");
        assert_eq!(plan.legacy_doors, vec![RecoveryPath::Phrase]);
        apply(&paths, &plan, TEST_PASSPHRASE, None).expect("rewrap");

        // The self door opens at the NEW cost...
        vault.unlock(TEST_PASSPHRASE).expect("self door still opens");
        // ...the phrase door opens at the OLD cost, from params.toml...
        vault
            .unlock_with_recovery(&tmp.phrase)
            .expect("the v1 phrase door still opens");
        // ...because params.toml was never touched.
        assert_eq!(
            std::fs::read(paths.params()).unwrap(),
            params_before,
            "a rewrap must write exactly one file"
        );
    }

    #[test]
    fn a_pre_rewrap_bundle_still_verifies_after_the_vault_moves_on() {
        // The case slice 005's deferred verification calls out as the one most
        // likely to be got wrong: an escrow bundle exported before rehardening
        // is a valid historical artifact and must keep opening on its own
        // terms, whatever the live vault has done since.
        let (tmp, vault) = vault_with_v1_doors();
        let paths = vault.paths().clone();

        let dest = tmp.dir.path().join("pre-rewrap.toml");
        escrow::export(&paths, Some("garden-abc"), &dest, true).expect("export");

        let plan = plan(
            &paths,
            Argon2Params {
                m_cost: 64,
                t_cost: 3,
                p_cost: 1,
            },
            true,
        )
        .expect("plan");
        apply(&paths, &plan, TEST_PASSPHRASE, None).expect("rewrap");

        let raw = std::fs::read_to_string(&dest).unwrap();
        let bundle = escrow::parse(&raw).expect("parse");
        assert!(escrow::check_integrity(&bundle).is_intact());
        escrow::prove_openable(&bundle, TEST_PASSPHRASE)
            .expect("a bundle exported before the rewrap still opens");
    }

    #[test]
    fn a_post_rewrap_bundle_opens_though_its_params_member_disagrees() {
        // The mirror image, and the reason `prove_openable` needed no change:
        // after a rewrap the bundle carries a v2 `k.self` beside a `params.toml`
        // member describing the OLD costs, because a rewrap deliberately leaves
        // `params.toml` alone. A verifier that trusted the member would fail
        // here; one that prefers what the wrapping carries does not.
        let (tmp, vault) = vault_with_v1_doors();
        let paths = vault.paths().clone();

        let target = Argon2Params {
            m_cost: 64,
            t_cost: 3,
            p_cost: 1,
        };
        let plan = plan(&paths, target, true).expect("plan");
        apply(&paths, &plan, TEST_PASSPHRASE, None).expect("rewrap");

        let dest = tmp.dir.path().join("post-rewrap.toml");
        escrow::export(&paths, Some("garden-abc"), &dest, true).expect("export");
        let raw = std::fs::read_to_string(&dest).unwrap();
        let bundle = escrow::parse(&raw).expect("parse");

        let member_bytes = bundle.member("params.toml").unwrap().decoded().unwrap();
        let member: VaultParams =
            toml::from_str(std::str::from_utf8(&member_bytes).unwrap()).unwrap();
        assert_ne!(
            member.argon2, target,
            "the fixture is only meaningful if the member really does disagree"
        );

        assert!(escrow::check_integrity(&bundle).is_intact());
        escrow::prove_openable(&bundle, TEST_PASSPHRASE)
            .expect("the embedded costs win over the params.toml member");
    }

    #[test]
    fn a_rewrap_invalidates_an_outstanding_relock_blob() {
        // `vault_fingerprint` hashes `k.self` alone, so this is true by
        // construction — pinned here so it stays announced rather than
        // discovered at the next `softfig daemon cycle`.
        let (_tmp, vault) = vault_with_v1_doors();
        let paths = vault.paths().clone();
        let session = vault.unlock(TEST_PASSPHRASE).expect("unlock");
        let (token, blob) = session.mint_relock(1_000, 600).expect("mint");
        let encoded = blob.encode();
        vault
            .redeem_relock(&token, &encoded, 1_100)
            .expect("the token works before the rewrap");

        let plan = plan(
            &paths,
            Argon2Params {
                m_cost: 64,
                t_cost: 3,
                p_cost: 1,
            },
            true,
        )
        .expect("plan");
        apply(&paths, &plan, TEST_PASSPHRASE, None).expect("rewrap");

        assert!(matches!(
            vault.redeem_relock(&token, &encoded, 1_100),
            Err(VaultError::AuthFailed)
        ));
    }

    #[test]
    fn the_plan_reports_a_current_escrow_proof_it_is_about_to_make_historical() {
        let (tmp, vault) = vault_with_v1_doors();
        let paths = vault.paths().clone();

        let plan_before = plan(&paths, Argon2Params { m_cost: 64, t_cost: 3, p_cost: 1 }, true)
            .expect("plan");
        assert!(
            !plan_before.invalidates_escrow_proof,
            "nothing has been proved yet"
        );

        let dest = tmp.dir.path().join("certify.toml");
        escrow::export(&paths, Some("garden-abc"), &dest, true).expect("export");
        let raw = std::fs::read(&dest).unwrap();
        let bundle = escrow::parse(std::str::from_utf8(&raw).unwrap()).unwrap();
        let report = escrow::check_integrity(&bundle);
        escrow::record_verification(
            &paths,
            crate::escrow::VerificationRecord {
                bundle_blake3: escrow::bundle_blake3(&raw),
                self_blake3: report.self_blake3.clone(),
                garden_id: bundle.garden_id.clone(),
                policy: bundle.policy.clone(),
                member_count: bundle.members.len(),
                outcome: escrow::OUTCOME_OPENABLE.to_string(),
                verified_at: 0,
            },
            1_700_000_000,
        )
        .expect("record");

        let plan_after = plan(&paths, Argon2Params { m_cost: 64, t_cost: 3, p_cost: 1 }, true)
            .expect("plan");
        assert!(plan_after.invalidates_escrow_proof);

        // And the proof really does stop counting once the rewrap lands, which
        // is what makes `vault recovery drop` refuse afterwards.
        apply(&paths, &plan_after, TEST_PASSPHRASE, None).expect("rewrap");
        let proof = escrow::current_proof(&paths).expect("read");
        assert!(proof.record.is_none());
        assert!(proof.stale, "the old proof is historical, not absent");
    }

    #[test]
    fn calibration_lands_in_the_band_or_says_it_clamped() {
        // A wall-clock assertion on a shared machine is a flake, so the
        // assertion is deliberately loose and carries the honest escape hatch:
        // a target the hardware cannot reach between the floor and the cap is
        // reported as clamped rather than silently missed.
        let c = calibrate(400, 3, 1).expect("calibration runs");
        assert!(c.params.at_least_as_strong_as(OWASP_BASELINE));
        assert!(
            c.clamped || c.measured_ms <= 400 * 4,
            "unclamped calibration should be near the target: {c:?}"
        );
    }

    /// A vault whose two doors are both in the pre-embedding format, i.e. what
    /// every vault on disk looked like before this slice.
    fn vault_with_v1_doors() -> (LegacyVault, crate::Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let params = VaultParams {
            format_version: crate::params::CURRENT_FORMAT_VERSION,
            argon2: Argon2Params {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        };
        let (vault, session, phrase) =
            crate::Vault::init_with_params(dir.path(), TEST_PASSPHRASE, params.clone())
                .expect("init");
        let paths = vault.paths().clone();

        // `init` writes v2 now, so wind both doors back to v1 to reproduce a
        // vault created before this slice.
        for (path, secret, purpose) in [
            (
                paths.kek_self(),
                TEST_PASSPHRASE.to_vec(),
                aad::KEK_SELF,
            ),
            (
                paths.kek_recovery(),
                phrase.as_passphrase_bytes().to_vec(),
                aad::KEK_RECOVERY,
            ),
        ] {
            let blob = kek::wrap_kek_under_passphrase_v1(
                &secret,
                &session.kek,
                &params.argon2,
                purpose,
            );
            std::fs::write(path, blob).expect("write v1 door");
        }
        drop(session);

        vault.unlock(TEST_PASSPHRASE).expect("the v1 fixture opens");
        (LegacyVault { dir, phrase }, vault)
    }

    struct LegacyVault {
        dir: tempfile::TempDir,
        phrase: RecoveryPhrase,
    }
}
