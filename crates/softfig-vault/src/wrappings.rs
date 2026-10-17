//! Adding and removing doors into `K`.
//!
//! Slice 001 described the recovery shape, 002 copied it somewhere safe, and
//! 003 proved the copy opens. This module is the one that *changes* the shape,
//! which makes it the only place in the milestone that can make a garden less
//! recoverable than it was — so every guard here is a hard refusal rather than
//! a prompt, and all of them are evaluated before anything on disk moves.
//!
//! # What authorizes a removal
//!
//! Not the door being removed. A `k.recovery` whose phrase is lost cannot be
//! opened, and requiring the lost phrase in order to delete the lock it opens
//! would strand exactly the state this milestone exists to fix. Removal is
//! authorized by the **live session** — you are already inside — plus a
//! *proven* escrow copy of a door that will still be there afterwards.
//!
//! # Why "escrow-verified" means the passphrase door
//!
//! [`crate::escrow::prove_openable`] proves one thing: `K` unwraps from the
//! bundle's `k.self` under the master passphrase. So a record written with
//! [`crate::escrow::OUTCOME_OPENABLE`] certifies the **passphrase** door and
//! nothing else, and it certifies it only while its `self_blake3` still
//! matches the `k.self` on disk — a proof of the door a `recover` replaced is
//! a historical fact, not a current guarantee. Everything the drop guard
//! decides follows from those two sentences.
//!
//! A consequence worth stating plainly: dropping the **passphrase** door is
//! refused today no matter what, because the door that would remain is one no
//! verb in this codebase can prove. That is the guard working, not a gap in
//! it.

use std::path::Path;

use crate::error::{Result, VaultError};
use crate::escrow::{self, VerificationRecord};
use crate::kek::{self, WrappingParams};
use crate::params::{aad, Argon2Params};
use crate::recovery::RecoveryPhrase;
use crate::recovery_policy::{
    self, DeclaredPolicy, RecoveryPath, RecoveryPolicy, RecoveryStatus, Wrappings,
};
use crate::session::VaultSession;
use crate::storage::{self, VaultPaths};

/// Key material mode. Every wrapping of `K` reaches disk through
/// [`write_wrapping`], so this is the mode of every door in the vault —
/// including the two `init` writes, which used a bare `fs::write`, and so the
/// process umask, until the same publish path was applied to them.
pub(crate) const WRAPPING_MODE: u32 = 0o600;

/// The one way a wrapping of `K` is published: crash-atomic, and private from
/// its first byte on disk.
///
/// One writer for the same reason [`crate::kek::wrap_kek_under_passphrase`] is
/// one writer. A door written a second way is a door with a second set of
/// properties, and the properties here — never torn, never even briefly
/// group-readable — are the ones that matter on the day the vault is all that
/// is left.
pub(crate) fn write_wrapping(path: &Path, bytes: &[u8]) -> Result<()> {
    storage::atomic_write_mode(path, bytes, WRAPPING_MODE)
}

/// The parameters `k.self` opens under today, and whether it carries them.
///
/// Reads two files and opens nothing, so it stays usable on a locked vault.
/// `Err` when either is unreadable, which is the right posture for a *reader*
/// — `vault status` and `rewrap`'s plan report an absent `k.self` rather than
/// substituting a default for it.
pub fn self_wrapping_params(paths: &VaultPaths) -> Result<WrappingParams> {
    let fallback = storage::load_params(paths)?.argon2;
    Ok(kek::wrapping_params(
        &std::fs::read(paths.kek_self())?,
        &fallback,
    ))
}

/// The parameters a **new** door should be minted under: the ones `k.self`
/// opens under today, falling back to `params.toml` when it does not carry its
/// own.
///
/// A vault is only as strong as its weakest door, so a door created now
/// inherits the vault's *current* posture rather than its birth posture. Since
/// a rewrap deliberately leaves `params.toml` at the birth cost (see
/// [`crate::rewrap`] for why it must), taking the cost from the file instead of
/// from the door would mean every [`crate::Vault::recover`] silently undid the
/// last rehardening, and every re-added phrase door was the weakest thing in
/// the vault — the exact inverse of the argument this milestone makes about
/// which door is worth worrying about.
///
/// Degrades instead of failing, deliberately: `recover` is the repair path for
/// a `k.self` that is missing or torn, so *needing* to read `k.self` in order
/// to replace it would strand the one case the verb exists for.
pub(crate) fn new_door_params(paths: &VaultPaths, fallback: &Argon2Params) -> Argon2Params {
    match std::fs::read(paths.kek_self()) {
        Ok(bytes) => kek::wrapping_params(&bytes, fallback).params,
        Err(_) => *fallback,
    }
}

/// What a removal would do, and what licenses it.
///
/// Produced by [`plan_drop`] so a caller can show the user exactly which door
/// is going and exactly what is left — `spec-trust.md`'s consent-environment
/// reasoning applied to key material: destructive operations are consented
/// individually and specifically, never as a blanket yes.
#[derive(Debug, Clone)]
pub struct DropPlan {
    /// The door being removed.
    pub removing: RecoveryPath,
    /// The file that will be unlinked.
    pub location: &'static str,
    /// The doors that will still exist afterwards, in canonical order.
    pub remaining: Vec<RecoveryPath>,
    /// The escrow proof that licenses this removal.
    pub certified_by: VerificationRecord,
}

/// Evaluate every guard and return what the removal would do. Touches nothing.
///
/// `authenticated_through` is the door the caller's live session came in by —
/// the CLI unlocks with the master passphrase, so it is
/// [`RecoveryPath::Passphrase`] there.
pub fn plan_drop(
    paths: &VaultPaths,
    target: RecoveryPath,
    authenticated_through: RecoveryPath,
) -> Result<DropPlan> {
    // Peer wrappings belong to the trust-matrix ledger, whose approval rules
    // this verb does not implement. Refusing is the honest answer; a
    // half-implemented removal of another device's copy of K is not.
    if target == RecoveryPath::Peers {
        return Err(VaultError::PeerWrappingUnsupported);
    }

    // A door change brings the declaration along with it, so there has to be
    // one, and it has to be readable. Checked here (before any prompt) and
    // again in `drop_wrapping` (before the unlink): an undeclared or corrupt
    // recovery.toml is refused, never silently written over.
    let _ = policy_to_edit(paths)?;

    let wrappings = Wrappings::read(paths);
    if !wrappings.contains(target) {
        return Err(VaultError::WrappingAbsent(target));
    }

    // Guard 1: a vault with no way into K is unrecoverable by construction.
    // The tool must not be able to produce that state at all.
    let remaining: Vec<RecoveryPath> = RecoveryPath::ALL
        .into_iter()
        .filter(|p| *p != target && wrappings.contains(*p))
        .collect();
    if remaining.is_empty() {
        return Err(VaultError::LastWrapping(target));
    }

    // Guards 2 and 3 both turn on the same fact — whether a *proven* door
    // survives the removal — so the proof is looked up once and the more
    // specific refusal is reported first. Someone removing the door they are
    // standing in needs to hear that, not a lecture about escrow records.
    let proof = current_escrow_proof(paths);
    let certified = RecoveryPath::Passphrase;
    let proven_door_survives = proof.is_ok() && remaining.contains(&certified);

    // Guard 3: never remove the door the session came in through unless what
    // remains is both present and proven. A mistyped command in an unlocked
    // session must not be able to close the session's own way back in.
    if target == authenticated_through && !proven_door_survives {
        return Err(VaultError::AuthenticatedWrapping(target));
    }

    // Guard 2: a proven copy of a door that will REMAIN has to exist. Removing
    // a door is only safe when what is left has been shown to open.
    let certified_by = proof?;
    if !remaining.contains(&certified) {
        return Err(VaultError::NoVerifiedEscrow {
            removing: target,
            reason: format!(
                "the only verified escrow copy proves the '{certified}' door, which is the one \
                 being removed — nothing proves the {} that would remain",
                describe(&remaining)
            ),
        });
    }

    Ok(DropPlan {
        removing: target,
        location: target.location(),
        remaining,
        certified_by,
    })
}

/// The declared policy these verbs will bring along with the door change.
///
/// `drop_wrapping` and `add_phrase` both re-write `recovery.toml` after the
/// door moves, so both need a declaration that is actually there and actually
/// parseable. An undeclared vault is refused with a pointer to `recovery
/// declare`, and an unreadable one is refused rather than overwritten: a
/// declaration is a human act, and the design rule slice 001 recorded is that
/// nothing writes one on the user's behalf.
fn policy_to_edit(paths: &VaultPaths) -> Result<RecoveryPolicy> {
    match recovery_policy::load_declared_policy(paths) {
        DeclaredPolicy::Declared(policy) => Ok(policy),
        DeclaredPolicy::Undeclared => Err(VaultError::NoUsableDeclaration(
            "no recovery.toml exists — declare the vault's recovery shape with \
             'vault recovery declare' first, so changing a door never writes a \
             declaration on your behalf"
                .to_string(),
        )),
        DeclaredPolicy::Unreadable(reason) => Err(VaultError::NoUsableDeclaration(format!(
            "recovery.toml exists but cannot be read ({reason}); fix or remove it before \
             changing doors — a declaration this build could not read must not be \
             silently replaced"
        ))),
    }
}

/// Remove a wrapping and bring the declared policy along with it.
///
/// Re-evaluates every guard itself: a caller that skipped [`plan_drop`], or
/// whose plan went stale while a human read the confirmation prompt, must not
/// be able to reach the filesystem with a stale answer.
///
/// **Order is a safety property.** All guards — including the declaration
/// read, which refuses an undeclared or unreadable `recovery.toml` while the
/// door is still in place — then the unlink, then the declaration. A crash in
/// the window leaves the policy promising a door that
/// is gone — which slice 001 reports as a `Promised` divergence, loudly. The
/// other order would leave a live, undeclared door instead: also divergent,
/// but an unaccounted way into the garden is the worse of the two states.
pub fn drop_wrapping(
    session: &VaultSession,
    target: RecoveryPath,
    authenticated_through: RecoveryPath,
) -> Result<DropPlan> {
    let paths = &session.paths;
    let plan = plan_drop(paths, target, authenticated_through)?;

    // Read before the unlink: a vault whose declaration cannot be edited
    // refuses with every door still where it was, not after removing one.
    let mut policy = policy_to_edit(paths)?;

    std::fs::remove_file(paths.root.join(plan.location))?;

    policy.remove(target);
    recovery_policy::store_declared_policy(paths, &policy)?;
    Ok(plan)
}

/// Wrap `K` under a fresh recovery phrase, write `k.recovery`, and declare it.
///
/// The mirror of [`crate::Vault::recover`] — same "re-wrap the KEK under a new
/// secret" move, pointed the other way. The phrase is returned once and never
/// stored; the caller shows it and drops it.
///
/// Refuses when a phrase wrapping already exists. Replacing a door is `drop`
/// then `add`, said out loud, so a live door is never silently swapped out
/// from under whoever wrote the old phrase down.
///
/// The new door is minted at [`new_door_params`] — the strength `k.self` has
/// now, not the strength the vault was born with. A phrase door added after a
/// rewrap is the one most likely to be added at the wrong cost, because the
/// milestone's own advice is to drop the phrase door and reharden: re-adding
/// one afterwards must not quietly reopen the vault at the old cost.
pub fn add_phrase(session: &VaultSession) -> Result<RecoveryPhrase> {
    let paths = &session.paths;
    check_can_add(paths, RecoveryPath::Phrase)?;
    // The declaration this change will bring along is read before anything
    // moves: on an undeclared or unreadable vault the whole operation
    // refuses (see [`policy_to_edit`]) instead of writing a declaration the
    // user never made.
    let mut policy = policy_to_edit(paths)?;
    let params = storage::load_params(paths)?;
    let target = new_door_params(paths, &params.argon2);

    let phrase = RecoveryPhrase::generate();
    let wrapped = kek::wrap_kek_under_passphrase(
        &phrase.as_passphrase_bytes(),
        &session.kek,
        &target,
        aad::KEK_RECOVERY,
    )?;
    // Door first, declaration second: a crash in the window leaves a working
    // door that the policy does not name, which slice 001 reports as an
    // `Undeclared` divergence. Nothing is lost and the gap is visible.
    write_wrapping(&paths.kek_recovery(), &wrapped)?;

    policy.insert(RecoveryPath::Phrase);
    recovery_policy::store_declared_policy(paths, &policy)?;
    Ok(phrase)
}

/// Adding a passphrase door is not a thing: `k.self` always exists, and
/// changing the secret behind it is [`crate::Vault::recover`]. Peer doors are
/// the ledger's. Naming both beats a generic refusal.
pub fn add_wrapping(session: &VaultSession, target: RecoveryPath) -> Result<RecoveryPhrase> {
    check_can_add(&session.paths, target)?;
    match target {
        RecoveryPath::Phrase => add_phrase(session),
        // Unreachable: `check_can_add` rejects both above. Kept total rather
        // than `unreachable!()` so a new `RecoveryPath` variant is a compile
        // error here, not a panic in a key-management verb.
        RecoveryPath::Peers => Err(VaultError::PeerWrappingUnsupported),
        RecoveryPath::Passphrase => Err(VaultError::WrappingExists(RecoveryPath::Passphrase)),
    }
}

/// Whether a door can be added, decided without a session.
///
/// Separate so a caller can refuse *before* prompting: making someone type a
/// passphrase only to be told the door already exists is a prompt that teaches
/// people to type passphrases at prompts they have not read.
pub fn check_can_add(paths: &VaultPaths, target: RecoveryPath) -> Result<()> {
    match target {
        RecoveryPath::Peers => Err(VaultError::PeerWrappingUnsupported),
        // `k.self` always exists; changing the secret behind it is `recover`.
        RecoveryPath::Passphrase => Err(VaultError::WrappingExists(RecoveryPath::Passphrase)),
        RecoveryPath::Phrase if paths.kek_recovery().exists() => {
            Err(VaultError::WrappingExists(RecoveryPath::Phrase))
        }
        RecoveryPath::Phrase => Ok(()),
    }
}

/// The escrow proof that currently certifies this vault's passphrase door, or
/// the reason there isn't one.
///
/// "Currently" is the whole point: a record whose `self_blake3` no longer
/// matches the `k.self` on disk proved a door that has since been replaced. It
/// remains a true statement about a copy that exists somewhere, and it is not
/// a licence to remove anything today.
fn current_escrow_proof(paths: &VaultPaths) -> Result<VerificationRecord> {
    let proof = escrow::current_proof(paths)?;
    if let Some(record) = proof.record {
        return Ok(record);
    }
    Err(VaultError::NoVerifiedEscrow {
        removing: RecoveryPath::Phrase,
        reason: if proof.stale {
            format!(
                "every verified escrow copy on record proves an older {} than this vault has \
                 now — re-export and re-verify before removing a door",
                storage::KEK_SELF_FILE
            )
        } else {
            "no escrow copy of this vault has been proved to open: run 'vault escrow export' \
             then 'vault escrow verify' on the copy first"
                .to_string()
        },
    })
}

fn describe(paths: &[RecoveryPath]) -> String {
    match paths {
        [] => "nothing".to_string(),
        [one] => format!("'{one}' door"),
        many => format!(
            "'{}' doors",
            many.iter()
                .map(|p| p.token())
                .collect::<Vec<_>>()
                .join("' and '")
        ),
    }
}

/// The declared policy and the doors on disk, after an operation. Callers
/// report this so the user sees the shape they now have, not the one they
/// asked for.
pub fn shape_now(paths: &VaultPaths) -> (RecoveryPolicy, Wrappings) {
    let status = RecoveryStatus::read(paths);
    (status.effective(), status.wrappings)
}
