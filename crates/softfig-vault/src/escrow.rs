//! The escrow bundle — every wrapping of `K`, in one file safe to copy anywhere.
//!
//! # What this is for
//!
//! A garden whose only door is the master passphrase is not recoverable from
//! the passphrase alone: the passphrase opens `k.self`, and `k.self` is 88
//! bytes that exist on exactly one device. No server holds a copy. Losing
//! those bytes is the one unrecoverable failure in the system, and it is a
//! failure the operator cannot see coming — a vault that unlocks every day
//! looks identical to one whose only copy is on a dying eMMC.
//!
//! Escrow makes that failure survivable by making the key material a small,
//! inert, self-describing artifact: about a kilobyte, static between
//! rotations, and useless to anyone who does not know the passphrase. That
//! combination is what licenses copying it *to excess* — every backup target,
//! the SD card, base64 on paper.
//!
//! # This opens nothing
//!
//! Export is a **file-copy-and-describe operation, not a crypto operation**.
//! Every member is already sealed ciphertext (`k.self`, `k.recovery`,
//! `master/*.key`, `identity.key`, `transport.key`, `shared-keys/*.key`) or
//! non-secret parameters (`params.toml`, `active.toml`, `recovery.toml`), so
//! nothing here takes a passphrase or constructs a session. That is not an
//! optimization: it is what lets you escrow a vault you **cannot currently
//! open**, which is exactly the moment escrow is worth having.
//!
//! # Format
//!
//! One TOML document: a plaintext comment banner explaining the artifact to
//! whoever finds it, then the manifest, then each member as a `[[member]]`
//! row with its bytes base64-inline. Comments are TOML, so parsing the whole
//! file is a single `toml::from_str` — no custom framing, no offsets.
//!
//! The bytes are **deterministic**: same vault state, same bundle, byte for
//! byte. There is deliberately no export timestamp inside the file (the
//! file's own mtime is the copy time), because an in-band timestamp would
//! make two exports of an unchanged vault differ forever, defeating both
//! comparison and content-addressing of an artifact whose whole point is
//! being copied many times.
//!
//! Members are an **allowlist**, never a directory scan — that is what keeps
//! `sealed-paths.toml`, stray files, and anything else that lands in the
//! vault directory out of the bundle by construction rather than by a filter
//! someone has to remember to update.
//!
//! See `growlight/backlog/milestones/vault-recovery-policy/slices/002-escrow-export.md`
//! in the garden for the design locks this module transcribes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::kek::{self, Kek};
use crate::params::{aad, ActiveKey, VaultParams, CURRENT_FORMAT_VERSION, KEY_LEN};
use crate::recovery_policy::{DeclaredPolicy, RecoveryPath, RecoveryPolicy, RecoveryStatus};
use crate::storage::{self, VaultPaths};

/// On-disk schema version of the escrow bundle. Independent of the vault's
/// [`crate::params::CURRENT_FORMAT_VERSION`] and of
/// [`crate::recovery_policy::RECOVERY_POLICY_FORMAT_VERSION`]: this is a
/// separate artifact with a separate lifetime, and a bundle written today
/// must stay readable across vault-format changes.
pub const ESCROW_FORMAT_VERSION: u32 = 1;

/// `policy_source` when a human declared the shape.
pub const SOURCE_DECLARED: &str = "declared";
/// `policy_source` when the shape was read off the disk instead.
pub const SOURCE_INFERRED: &str = "inferred";

/// Published mode of the bundle. Inert without the passphrase, but it is key
/// material: it gets key-material permissions.
const BUNDLE_MODE: u32 = 0o600;

/// The plaintext header. Written for someone who finds this file years from
/// now with no soft-fig installed and no memory of what it was — which is a
/// realistic way for a recovery artifact to be encountered, and the reason
/// the explanation rides *inside* the bundle rather than in documentation
/// that will not be next to it.
const BANNER: &str = "\
# ============================================================================
# soft-fig vault escrow bundle
# ============================================================================
#
# WHAT THIS IS
#   Every key file of one soft-fig vault, base64-inlined into this single TOML
#   document, with a manifest naming each file, its permissions, its length,
#   and its BLAKE3 hash.
#
# IS IT SECRET?
#   Every `data` value below is either sealed ciphertext or non-secret
#   parameters. None of it opens without that vault's master passphrase. The
#   passphrase is NOT in this file and cannot be derived from it, and no
#   server anywhere holds a copy of it. This bundle is INERT WITHOUT THE
#   PASSPHRASE. That is what makes it safe to copy to excess -- and copying it
#   to excess is exactly what it is for.
#
# WHAT IS IT FOR?
#   Recovering this vault needs BOTH the master passphrase AND these bytes:
#   the passphrase opens `k.self`, and `k.self` is what holds the key. A
#   passphrase with no copy of these bytes opens nothing. This file is about a
#   kilobyte. Put it on every backup target you have. Print it.
#
# HOW TO RESTORE IT
#   Recreate each `[[member]]` under `<state-root>/.softfig/vault/` at the
#   path in `name`, with its bytes base64-decoded and its permissions set to
#   `mode` (octal). Then unlock with the master passphrase as usual.
#
# HOW TO CHECK A COPY
#   Each member carries the BLAKE3 hash of its decoded bytes. The export also
#   printed the BLAKE3 of this whole file: two exports of an unchanged vault
#   are byte-identical, so copies can be compared by hash alone.
#
# WHY THERE IS NO DATE IN HERE
#   On purpose -- an in-band timestamp would make every export differ from
#   every other one, and comparing copies is worth more than a date. The
#   file's own modification time is when this copy was written.
# ============================================================================
";

/// One file from the vault directory, carried whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Path relative to the vault directory, `/`-separated
    /// (`k.self`, `master/1.key`).
    pub name: String,
    /// Permission bits as zero-padded octal (`600`). Recorded so a restore
    /// can recreate the file correctly even though the bundle may have
    /// travelled across a filesystem that cannot hold modes — the vfat SD
    /// card this artifact is meant to live on, for one.
    pub mode: String,
    /// Length of the decoded bytes.
    pub size: u64,
    /// BLAKE3 of the decoded bytes, hex.
    pub blake3: String,
    /// The file itself, base64 (standard alphabet, padded).
    pub data: String,
}

impl Member {
    /// The member's real bytes.
    pub fn decoded(&self) -> Result<Vec<u8>> {
        B64.decode(self.data.as_bytes())
            .map_err(|e| VaultError::EscrowMalformed(format!("member '{}': {e}", self.name)))
    }

    /// The recorded permission bits.
    pub fn mode_bits(&self) -> Result<u32> {
        u32::from_str_radix(&self.mode, 8).map_err(|e| {
            VaultError::EscrowMalformed(format!(
                "member '{}': mode {:?} is not octal: {e}",
                self.name, self.mode
            ))
        })
    }
}

/// The whole bundle. Field order is the on-disk order: scalars first, then
/// the `[[member]]` rows, which is both what TOML requires and what makes
/// the output deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowBundle {
    pub format_version: u32,
    /// The store's `repo_id`, or empty when it could not be read. Empty is a
    /// legitimate state: a vault directory with no database beside it still
    /// escrows, it just cannot say which garden it belongs to.
    pub garden_id: String,
    /// The effective recovery policy, canonical form (`passphrase-only`).
    pub policy: String,
    /// [`SOURCE_DECLARED`] or [`SOURCE_INFERRED`] — whether a human stated
    /// the shape above or it was read off the wrappings present. Recording
    /// which is the same honesty `vault status` owes: an inferred shape can
    /// never report a missing door.
    pub policy_source: String,
    /// Why the policy is inferred, when it is. Absent from the file when the
    /// policy was declared.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_note: String,
    pub member_count: usize,
    #[serde(rename = "member", default)]
    pub members: Vec<Member>,
}

impl EscrowBundle {
    /// The member with this name, if it rode along.
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }
}

/// What was written, for the CLI to report. Absent members matter as much as
/// present ones — "no `k.recovery`" is the fact the operator most needs to
/// see on a passphrase-only garden.
#[derive(Debug, Clone)]
pub struct ExportSummary {
    pub dest: PathBuf,
    pub garden_id: String,
    pub policy: String,
    pub policy_source: String,
    pub policy_note: String,
    /// Names carried, in canonical order.
    pub members: Vec<String>,
    /// Allowlisted names that were not on disk.
    pub absent: Vec<String>,
    /// Size of the written bundle.
    pub bytes: u64,
    /// BLAKE3 of the whole file, hex — the handle for comparing copies.
    pub bundle_blake3: String,
}

/// Write the escrow bundle for the vault at `paths` to `dest`.
///
/// `garden_id` is the store's `repo_id` when the caller could read it; this
/// crate stays free of the store dependency, so the CLI supplies it. `None`
/// exports an unlabelled bundle rather than failing.
///
/// Takes no passphrase and opens no wrapping. Refuses to clobber a *different*
/// existing bundle unless `force` — escrow copies are redundancy, and silently
/// overwriting one destroys the only record of an earlier vault state.
/// Rewriting a byte-identical bundle is a no-op, not a conflict.
pub fn export(
    paths: &VaultPaths,
    garden_id: Option<&str>,
    dest: &Path,
    force: bool,
) -> Result<ExportSummary> {
    // `params.toml` is the "this is a vault" gate: without it there is no
    // vault here to escrow, only a directory.
    if !paths.exists() {
        return Err(VaultError::NotInitialized(paths.root.clone()));
    }

    let status = RecoveryStatus::read(paths);
    let (policy_source, policy_note) = match &status.declared {
        DeclaredPolicy::Declared(_) => (SOURCE_DECLARED, String::new()),
        DeclaredPolicy::Undeclared => (
            SOURCE_INFERRED,
            "no recovery.toml on disk: the policy above was read off the wrappings \
             present, not stated by anyone"
                .to_string(),
        ),
        // The declaration rides along verbatim as a member either way — a
        // copy of a strange state beats no copy of it — and the manifest
        // records that it could not be read rather than refusing to export.
        DeclaredPolicy::Unreadable(reason) => (
            SOURCE_INFERRED,
            format!(
                "recovery.toml is present but could not be read ({reason}): the policy \
                 above was read off the wrappings present"
            ),
        ),
    };

    let mut members = Vec::new();
    let mut absent = Vec::new();
    for name in member_names(paths)? {
        match read_member(&paths.root, &name)? {
            Some(m) => members.push(m),
            None => absent.push(name),
        }
    }

    let bundle = EscrowBundle {
        format_version: ESCROW_FORMAT_VERSION,
        garden_id: garden_id.unwrap_or_default().to_string(),
        policy: status.effective().to_string(),
        policy_source: policy_source.to_string(),
        policy_note,
        member_count: members.len(),
        members,
    };

    let mut text = String::from(BANNER);
    text.push('\n');
    text.push_str(&toml::to_string_pretty(&bundle)?);
    let bytes = text.into_bytes();
    let bundle_blake3 = bundle_blake3(&bytes);

    if dest.exists() {
        let existing = fs::read(dest)?;
        if existing != bytes && !force {
            return Err(VaultError::EscrowTargetExists(dest.to_path_buf()));
        }
    }
    storage::atomic_write_mode(dest, &bytes, BUNDLE_MODE)?;

    Ok(ExportSummary {
        dest: dest.to_path_buf(),
        garden_id: bundle.garden_id,
        policy: bundle.policy,
        policy_source: bundle.policy_source,
        policy_note: bundle.policy_note,
        members: bundle.members.into_iter().map(|m| m.name).collect(),
        absent,
        bytes: bytes.len() as u64,
        bundle_blake3,
    })
}

/// Read a bundle back. Structural only — it decodes the document and checks
/// the format version. Whether the members are *intact* is
/// [`check_integrity`]; whether they *open* is [`prove_openable`]. Every
/// reader in this module starts here, so there is exactly one place that
/// knows the on-disk shape.
pub fn parse(text: &str) -> Result<EscrowBundle> {
    let bundle: EscrowBundle = toml::from_str(text)?;
    if bundle.format_version != ESCROW_FORMAT_VERSION {
        return Err(VaultError::EscrowMalformed(format!(
            "escrow format version {} is not the version this soft-fig writes ({ESCROW_FORMAT_VERSION})",
            bundle.format_version
        )));
    }
    Ok(bundle)
}

/// The allowlist, in canonical order: `params.toml`, `active.toml`,
/// `recovery.toml`, `k.self`, `k.recovery`, `identity.key`, `transport.key`,
/// `master/*` ascending by generation, `shared-keys/*` sorted, `peer-keks/*`
/// sorted.
///
/// Fixed order is what makes the bundle deterministic; an allowlist (rather
/// than a scan of the vault directory) is what keeps everything that is not
/// key material — `sealed-paths.toml`, editor droppings, a stray copy of
/// something — out of the artifact by construction.
///
/// `peer-keks/` is enumerated though nothing writes there yet: the peer path
/// is spec, and enumerating it means the day it becomes code, escrow already
/// carries it.
fn member_names(paths: &VaultPaths) -> Result<Vec<String>> {
    let mut names = vec![
        storage::PARAMS_FILE.to_string(),
        storage::ACTIVE_FILE.to_string(),
        storage::RECOVERY_POLICY_FILE.to_string(),
        storage::KEK_SELF_FILE.to_string(),
        storage::KEK_RECOVERY_FILE.to_string(),
        storage::IDENTITY_FILE.to_string(),
        storage::TRANSPORT_FILE.to_string(),
    ];
    // Every generation, not just the active one: historical commits name the
    // generation that sealed them (`master_key_id`), so dropping the old keys
    // would leave old blobs unreadable after a rotation.
    for id in storage::list_master_ids(paths)? {
        names.push(format!("{}/{id}.key", storage::MASTER_DIR));
    }
    for file in sorted_key_files(&paths.shared_keys_dir()) {
        names.push(format!("{}/{file}", storage::SHARED_KEYS_DIR));
    }
    for file in sorted_key_files(&paths.peer_keks_dir()) {
        names.push(format!("{}/{file}", storage::PEER_KEKS_DIR));
    }
    Ok(names)
}

/// `*.key` filenames in `dir`, sorted. A missing or unreadable directory
/// yields nothing: an absent `shared-keys/` is the normal case, not a fault.
fn sorted_key_files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".key") && entry.path().is_file() {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// One member, or `None` when that file is not present — absence is reported,
/// never fatal. A pre-M5a vault has no `transport.key`; a passphrase-only one
/// has no `k.recovery`; an undeclared one has no `recovery.toml`.
fn read_member(root: &Path, name: &str) -> Result<Option<Member>> {
    let path = root.join(name);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    Ok(Some(Member {
        name: name.to_string(),
        mode: format!("{:03o}", meta.permissions().mode() & 0o777),
        size: bytes.len() as u64,
        blake3: blake3::hash(&bytes).to_hex().to_string(),
        data: B64.encode(&bytes),
    }))
}

// ---------------------------------------------------------------------------
// Verification — `status` observes, `verify` proves.
//
// Export deliberately opens nothing, so every hash in a manifest is
// self-consistent by construction: re-hashing a bundle against its own
// manifest proves only that the file has not rotted since it was written.
// That is worth checking and it is not the question an operator has. The
// question is *"would this bundle actually reopen my vault?"*, and only an
// unwrap answers it — which is why verification is two stages, integrity and
// openability, and why the second one needs a passphrase.
//
// **Nothing here can touch a live vault.** The verification entry points take
// a parsed bundle and a passphrase; they hold no `VaultPaths`, open no file,
// and never materialise the bundle on disk. Non-destructiveness is therefore a
// property of the signatures rather than of the care taken inside them, and
// verifying a stale bundle against a rotated vault — a legitimate, expected
// operation — cannot "helpfully" repair anything. The one function that does
// write, [`record_verification`], is separate, explicit, and the caller's
// decision.
// ---------------------------------------------------------------------------

/// One thing wrong with a bundle. Every variant names the member (or field) at
/// fault, because the remedies differ completely: a corrupt member means the
/// medium is failing and another copy is needed; a missing declared door means
/// the bundle is an incomplete escrow of its own stated policy and needs
/// re-exporting; an unknown member means someone edited the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The member's bytes do not hash to the value in the manifest.
    Corrupt {
        name: String,
        expected: String,
        actual: String,
    },
    /// The member's `data` is not decodable base64.
    Undecodable { name: String, reason: String },
    /// The member decoded, but to a different length than the manifest claims.
    SizeMismatch {
        name: String,
        declared: u64,
        actual: u64,
    },
    /// A member name this soft-fig does not recognise. The allowlist is what
    /// keeps non-key-material out of a bundle; a name outside it means the file
    /// was written by something other than `escrow export`.
    Unknown { name: String },
    /// The same member name twice — a restore would have to pick one.
    Duplicate { name: String },
    /// `member_count` disagrees with the rows actually present.
    CountMismatch { declared: usize, actual: usize },
    /// A member the bundle is unusable without.
    Missing { name: String, why: &'static str },
    /// A member that is present but cannot be read as what it must be.
    Unreadable { name: String, reason: String },
    /// The declared policy names a door the bundle does not carry. Not a
    /// warning: a bundle that claims `passphrase+phrase` and carries no
    /// `k.recovery` is an escrow of a recovery shape that does not exist.
    MissingDoor { path: String, location: String },
    /// The manifest's `policy` field is not a policy this soft-fig can parse.
    PolicyUnreadable { policy: String, reason: String },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt {
                name,
                expected,
                actual,
            } => write!(
                f,
                "member '{name}' is corrupt: manifest says blake3 {expected}, the bytes hash to {actual}"
            ),
            Self::Undecodable { name, reason } => {
                write!(f, "member '{name}' is not decodable base64: {reason}")
            }
            Self::SizeMismatch {
                name,
                declared,
                actual,
            } => write!(
                f,
                "member '{name}' declares {declared} bytes but decodes to {actual}"
            ),
            Self::Unknown { name } => write!(
                f,
                "member '{name}' is not a name soft-fig escrows — this bundle was not written by 'vault escrow export'"
            ),
            Self::Duplicate { name } => {
                write!(f, "member '{name}' appears more than once")
            }
            Self::CountMismatch { declared, actual } => write!(
                f,
                "the manifest declares {declared} members but carries {actual}"
            ),
            Self::Missing { name, why } => {
                write!(f, "member '{name}' is missing — it holds {why}")
            }
            Self::Unreadable { name, reason } => {
                write!(f, "member '{name}' cannot be read: {reason}")
            }
            Self::MissingDoor { path, location } => write!(
                f,
                "the declared policy includes '{path}' but no {location} rides this bundle — it is not a complete escrow of that policy"
            ),
            Self::PolicyUnreadable { policy, reason } => {
                write!(f, "the manifest policy {policy:?} is unreadable: {reason}")
            }
        }
    }
}

/// What the bundle says about itself, plus everything wrong with it.
///
/// Produced without a passphrase: this is the half of verification that can be
/// run on a machine you do not trust, or on a copy whose vault you cannot
/// currently open.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    pub format_version: u32,
    pub garden_id: String,
    pub policy: String,
    pub policy_source: String,
    pub policy_note: String,
    /// Member names as they appear in the bundle.
    pub members: Vec<String>,
    /// Total decoded size of every member that decoded.
    pub key_material_bytes: u64,
    /// BLAKE3 of the `k.self` this bundle carries, computed from its bytes —
    /// empty when there is no such member. This is the handle a later slice
    /// uses to tell a current proof from one that predates a `recover` or a
    /// `rewrap`: the same vault, a different door.
    pub self_blake3: String,
    /// Doors carried that the declared policy does not mention. Reported, not
    /// failed: an unaccounted extra door is a fact worth surfacing, but it is
    /// not a gap in the escrow.
    pub undeclared_doors: Vec<String>,
    pub findings: Vec<Finding>,
}

impl IntegrityReport {
    /// No findings at all. Any finding fails the whole verification: a bundle
    /// with one bad member is not a backup, and offering a passphrase prompt
    /// on top of it would produce a half-green result an operator would read
    /// as "fine".
    pub fn is_intact(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Check a bundle against its own manifest and its own declared policy.
///
/// Takes no passphrase and opens no wrapping. Reports every problem it finds
/// rather than stopping at the first — a failing medium usually damages more
/// than one member, and knowing that is the difference between "re-copy this"
/// and "this card is dying".
pub fn check_integrity(bundle: &EscrowBundle) -> IntegrityReport {
    let mut findings = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut decoded: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    let mut key_material_bytes = 0u64;

    for m in &bundle.members {
        if !seen.insert(m.name.as_str()) {
            findings.push(Finding::Duplicate {
                name: m.name.clone(),
            });
            continue;
        }
        if !member_name_is_known(&m.name) {
            findings.push(Finding::Unknown {
                name: m.name.clone(),
            });
            continue;
        }
        let bytes = match m.decoded() {
            Ok(b) => b,
            Err(e) => {
                findings.push(Finding::Undecodable {
                    name: m.name.clone(),
                    reason: e.to_string(),
                });
                continue;
            }
        };
        if bytes.len() as u64 != m.size {
            findings.push(Finding::SizeMismatch {
                name: m.name.clone(),
                declared: m.size,
                actual: bytes.len() as u64,
            });
        }
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != m.blake3 {
            findings.push(Finding::Corrupt {
                name: m.name.clone(),
                expected: m.blake3.clone(),
                actual,
            });
        }
        key_material_bytes += bytes.len() as u64;
        decoded.insert(m.name.as_str(), bytes);
    }

    if bundle.member_count != bundle.members.len() {
        findings.push(Finding::CountMismatch {
            declared: bundle.member_count,
            actual: bundle.members.len(),
        });
    }

    // The two members nothing can be done without. `k.self` is deliberately
    // not in this list: a bundle with no passphrase door is describable (the
    // policy check below catches it when the policy claims one), and the
    // openability proof refuses on its own terms.
    for (name, why) in [
        (
            storage::PARAMS_FILE,
            "the Argon2 cost the passphrase must be stretched by",
        ),
        (
            storage::ACTIVE_FILE,
            "the pointer naming which master generation is current",
        ),
    ] {
        if !decoded.contains_key(name) {
            findings.push(Finding::Missing { name: name.to_string(), why });
        }
    }

    // The active generation must actually ride along, or the bundle restores a
    // vault that cannot read its own newest data.
    if let Some(bytes) = decoded.get(storage::ACTIVE_FILE) {
        match parse_toml::<ActiveKey>(bytes) {
            Ok(active) => {
                let name = master_member_name(active.master_key_id);
                if !decoded.contains_key(name.as_str()) {
                    findings.push(Finding::Missing {
                        name,
                        why: "the master key the active pointer names",
                    });
                }
            }
            Err(reason) => findings.push(Finding::Unreadable {
                name: storage::ACTIVE_FILE.to_string(),
                reason,
            }),
        }
    }

    // Every door the policy claims has to be here. This is the check that turns
    // "I declared passphrase+phrase" into a testable statement about the
    // artifact rather than a note in a file.
    let mut undeclared_doors = Vec::new();
    match RecoveryPolicy::parse(&bundle.policy) {
        Ok(policy) => {
            for path in RecoveryPath::ALL {
                let carried = door_is_carried(&decoded, path);
                match (policy.contains(path), carried) {
                    (true, false) => findings.push(Finding::MissingDoor {
                        path: path.token().to_string(),
                        location: path.location().to_string(),
                    }),
                    (false, true) => undeclared_doors.push(path.token().to_string()),
                    _ => {}
                }
            }
        }
        Err(e) => findings.push(Finding::PolicyUnreadable {
            policy: bundle.policy.clone(),
            reason: e.to_string(),
        }),
    }

    let self_blake3 = decoded
        .get(storage::KEK_SELF_FILE)
        .map(|b| blake3::hash(b).to_hex().to_string())
        .unwrap_or_default();

    IntegrityReport {
        format_version: bundle.format_version,
        garden_id: bundle.garden_id.clone(),
        policy: bundle.policy.clone(),
        policy_source: bundle.policy_source.clone(),
        policy_note: bundle.policy_note.clone(),
        members: bundle.members.iter().map(|m| m.name.clone()).collect(),
        key_material_bytes,
        self_blake3,
        undeclared_doors,
        findings,
    }
}

/// What an openability proof established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenProof {
    /// The generation `active.toml` points at — the one new data is written
    /// under, and the one proved first.
    pub active_master_key_id: u32,
    /// Every generation whose key was unwrapped under the recovered `K`,
    /// ascending. All of them, not just the active one: historical blobs name
    /// the generation that sealed them, so a bundle whose old generation does
    /// not open restores a vault that cannot read its own past.
    pub generations_proved: Vec<u32>,
    /// Doors carried by the bundle that this proof did **not** exercise,
    /// because they do not open under the master passphrase. Naming them is the
    /// difference between "the bundle is proved" and "the part of the bundle
    /// this verb can prove is proved".
    pub unproved_doors: Vec<String>,
}

/// Unwrap `K` from the bundle's own `k.self`, under the bundle's own Argon2
/// parameters, and then unwrap every master generation it carries.
///
/// This is the whole point of the verb. A bundle whose bytes are intact but
/// whose passphrase is misremembered, or whose `params.toml` was exported
/// inconsistently with its `k.self`, is worthless, and nothing short of an
/// unwrap detects it.
///
/// **[`VaultError::AuthFailed`] means exactly one thing here: the passphrase
/// did not open `k.self`.** Once `K` is recovered, a master generation that
/// fails to open is a defect in the bundle, not in the passphrase, and is
/// reported as [`VaultError::EscrowMalformed`] naming the member — collapsing
/// the two would tell someone to re-type a passphrase that was already right.
///
/// Holds no path and writes nothing; the recovered keys live in this function
/// and are zeroed when it returns.
pub fn prove_openable(bundle: &EscrowBundle, passphrase: &[u8]) -> Result<OpenProof> {
    let params: VaultParams = member_toml(bundle, storage::PARAMS_FILE)?;
    if params.format_version != CURRENT_FORMAT_VERSION {
        return Err(VaultError::UnsupportedFormat(params.format_version));
    }
    let active: ActiveKey = member_toml(bundle, storage::ACTIVE_FILE)?;

    let wrapped_self = member_bytes(bundle, storage::KEK_SELF_FILE)?;
    let kek = kek::unwrap_kek_under_passphrase(
        passphrase,
        &wrapped_self,
        &params.argon2,
        aad::KEK_SELF,
    )?;

    // Active first: it is the generation the proof is really about, so a
    // failure there should be the failure reported.
    let active_id = active.master_key_id;
    open_master(bundle, &kek, active_id)?;
    let mut generations_proved = vec![active_id];
    for id in carried_master_ids(bundle) {
        if id != active_id {
            open_master(bundle, &kek, id)?;
            generations_proved.push(id);
        }
    }
    generations_proved.sort_unstable();

    Ok(OpenProof {
        active_master_key_id: active_id,
        generations_proved,
        unproved_doors: unproved_doors(bundle),
    })
}

/// Unwrap one master generation under `K` and throw the result away — the
/// proof is that it opened at all.
fn open_master(bundle: &EscrowBundle, kek: &Kek, id: u32) -> Result<()> {
    let name = master_member_name(id);
    let wrapped = member_bytes(bundle, &name)?;
    let plaintext = Zeroizing::new(
        kek::unwrap_under_kek(kek, &wrapped, &aad::master(id)).map_err(|_| {
            VaultError::EscrowMalformed(format!(
                "member '{name}' did not open under the recovered K — the passphrase was right, \
                 so this member belongs to a different vault or has been substituted"
            ))
        })?,
    );
    if plaintext.len() != KEY_LEN {
        return Err(VaultError::EscrowMalformed(format!(
            "member '{name}' opened to {} bytes, not a {KEY_LEN}-byte key",
            plaintext.len()
        )));
    }
    Ok(())
}

/// Doors in the bundle that the master passphrase does not open.
fn unproved_doors(bundle: &EscrowBundle) -> Vec<String> {
    bundle
        .members
        .iter()
        .map(|m| m.name.as_str())
        .filter(|n| {
            *n == storage::KEK_RECOVERY_FILE || member_dir(n) == Some(storage::PEER_KEKS_DIR)
        })
        .map(str::to_string)
        .collect()
}

/// Generations carried by the bundle, ascending.
fn carried_master_ids(bundle: &EscrowBundle) -> Vec<u32> {
    let mut ids: Vec<u32> = bundle
        .members
        .iter()
        .filter_map(|m| master_generation(&m.name))
        .collect();
    ids.sort_unstable();
    ids
}

fn door_is_carried(decoded: &BTreeMap<&str, Vec<u8>>, path: RecoveryPath) -> bool {
    match path {
        RecoveryPath::Passphrase => decoded.contains_key(storage::KEK_SELF_FILE),
        RecoveryPath::Phrase => decoded.contains_key(storage::KEK_RECOVERY_FILE),
        RecoveryPath::Peers => decoded
            .keys()
            .any(|n| member_dir(n) == Some(storage::PEER_KEKS_DIR)),
    }
}

fn master_member_name(id: u32) -> String {
    format!("{}/{id}.key", storage::MASTER_DIR)
}

/// The directory component of a member name, if it has exactly one.
fn member_dir(name: &str) -> Option<&str> {
    let (dir, rest) = name.split_once('/')?;
    if rest.contains('/') {
        return None;
    }
    Some(dir)
}

/// The generation id of a `master/<id>.key` member.
fn master_generation(name: &str) -> Option<u32> {
    let (dir, file) = name.split_once('/')?;
    if dir != storage::MASTER_DIR || file.contains('/') {
        return None;
    }
    file.strip_suffix(".key")?.parse().ok()
}

/// Is this a member name `escrow export` would ever write?
///
/// The same allowlist [`member_names`] enumerates, expressed as a predicate
/// because a bundle is checked without a vault to enumerate against. It is also
/// the guard that keeps a hand-edited `../../etc/passwd` out of the member set
/// before a restore path ever treats these names as paths.
fn member_name_is_known(name: &str) -> bool {
    const FIXED: [&str; 7] = [
        storage::PARAMS_FILE,
        storage::ACTIVE_FILE,
        storage::RECOVERY_POLICY_FILE,
        storage::KEK_SELF_FILE,
        storage::KEK_RECOVERY_FILE,
        storage::IDENTITY_FILE,
        storage::TRANSPORT_FILE,
    ];
    if FIXED.contains(&name) {
        return true;
    }
    match member_dir(name) {
        Some(dir) if dir == storage::MASTER_DIR => master_generation(name).is_some(),
        Some(dir) if dir == storage::SHARED_KEYS_DIR || dir == storage::PEER_KEKS_DIR => name
            .rsplit_once('/')
            .and_then(|(_, file)| file.strip_suffix(".key"))
            .is_some_and(|stem| !stem.is_empty() && stem != "." && stem != ".."),
        _ => false,
    }
}

/// A member's decoded bytes, or a message naming what the bundle is missing.
fn member_bytes(bundle: &EscrowBundle, name: &str) -> Result<Vec<u8>> {
    bundle
        .member(name)
        .ok_or_else(|| {
            VaultError::EscrowMalformed(format!("this bundle carries no '{name}' to verify against"))
        })?
        .decoded()
}

fn member_toml<T: serde::de::DeserializeOwned>(bundle: &EscrowBundle, name: &str) -> Result<T> {
    let bytes = member_bytes(bundle, name)?;
    parse_toml(&bytes).map_err(|reason| {
        VaultError::EscrowMalformed(format!("member '{name}' cannot be read: {reason}"))
    })
}

fn parse_toml<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    toml::from_str(text).map_err(|e| e.to_string())
}

/// BLAKE3 of a whole bundle file, hex — the handle copies are compared by.
pub fn bundle_blake3(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// BLAKE3 of the `k.self` a live vault currently holds. Opens nothing, so it
/// stays usable on a locked vault; compare it against a record's
/// `self_blake3` to tell a current proof from a historical one.
pub fn current_self_blake3(paths: &VaultPaths) -> Result<String> {
    Ok(bundle_blake3(&fs::read(paths.kek_self())?))
}

/// The state of this vault's escrow proof relative to the `k.self` on disk
/// *right now*.
#[derive(Debug, Clone, Default)]
pub struct CurrentProof {
    /// A verified-openable record whose `self_blake3` still matches the live
    /// `k.self`. `Some` is a licence; `None` is not.
    pub record: Option<VerificationRecord>,
    /// A verified-openable record exists but describes an older `k.self`. The
    /// difference matters in the message: "no verified escrow" sends someone
    /// hunting for a record that is sitting right there.
    pub stale: bool,
}

/// Resolve [`CurrentProof`] for a vault. Opens nothing.
///
/// A proof is current only while its `self_blake3` matches the live `k.self`.
/// A record that proved the door a `recover` or `rewrap` replaced stays a true
/// statement about a copy that exists somewhere, and licenses nothing today.
/// `vault recovery drop` gates on this; `vault rewrap` warns that it is about
/// to move a current proof into the historical column.
pub fn current_proof(paths: &VaultPaths) -> Result<CurrentProof> {
    let live_self = current_self_blake3(paths)?;
    let log = read_verifications(paths)?;
    let mut out = CurrentProof::default();
    for entry in &log.entries {
        if entry.outcome != OUTCOME_OPENABLE {
            continue;
        }
        if entry.self_blake3 == live_self {
            out.record = Some(entry.clone());
            return Ok(out);
        }
        out.stale = true;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The verification record
// ---------------------------------------------------------------------------

/// On-disk schema of [`storage::ESCROW_RECORD_FILE`].
pub const ESCROW_RECORD_FORMAT_VERSION: u32 = 1;

/// The outcome written when a bundle proved both intact and openable. The only
/// outcome recorded today — failures are deliberately not written, because the
/// record exists to be *gated on*, and a file listing failures invites a reader
/// that forgets to check which kind it found.
pub const OUTCOME_OPENABLE: &str = "openable";

/// How many verifications to keep. Rotating a key or re-exporting produces a
/// new bundle hash, so the list would otherwise grow forever for no benefit;
/// the oldest entries are the least useful.
const MAX_VERIFICATION_RECORDS: usize = 16;

const RECORD_BANNER: &str = "\
# soft-fig — escrow verification record.
#
# One row per escrow bundle that has been proved both intact AND openable by
# `softfig vault escrow verify`. Hashes and times only: never bundle contents,
# never a passphrase.
#
# `self_blake3` is the hash of the `k.self` the verified bundle carried. When
# it stops matching this vault's current `k.self` the proof is historical --
# the copy is still a valid artifact of an older state, but it is no longer a
# proof that TODAY's vault can be reopened. Re-export and re-verify.
#
# `verified_at` is unix seconds. Written by soft-fig; edit at your own risk.
";

/// One proved bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRecord {
    /// BLAKE3 of the whole bundle file — its identity.
    pub bundle_blake3: String,
    /// BLAKE3 of the `k.self` it carried. See [`RECORD_BANNER`].
    pub self_blake3: String,
    /// The garden id the bundle claimed, matched against this vault's before
    /// the row was written.
    pub garden_id: String,
    /// The policy the bundle declared, as a canonical string.
    pub policy: String,
    pub member_count: usize,
    /// [`OUTCOME_OPENABLE`].
    pub outcome: String,
    /// Unix seconds.
    pub verified_at: i64,
}

/// The whole record file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EscrowLog {
    pub format_version: u32,
    #[serde(rename = "verification", default)]
    pub entries: Vec<VerificationRecord>,
}

impl EscrowLog {
    /// The most recently verified bundle.
    pub fn latest(&self) -> Option<&VerificationRecord> {
        self.entries.iter().max_by_key(|e| e.verified_at)
    }

    /// The record for one bundle, if it has ever been proved.
    pub fn verified(&self, bundle_blake3: &str) -> Option<&VerificationRecord> {
        self.entries
            .iter()
            .find(|e| e.bundle_blake3 == bundle_blake3)
    }
}

/// Read the record. An absent file is an empty log — "never verified" is a
/// state, not an error, and it is the state every vault starts in.
pub fn read_verifications(paths: &VaultPaths) -> Result<EscrowLog> {
    let raw = match fs::read_to_string(paths.escrow_record()) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(EscrowLog::default()),
        Err(e) => return Err(e.into()),
    };
    let log: EscrowLog = toml::from_str(&raw)?;
    if log.format_version != ESCROW_RECORD_FORMAT_VERSION {
        return Err(VaultError::EscrowMalformed(format!(
            "escrow record format version {} is not the version this soft-fig writes \
             ({ESCROW_RECORD_FORMAT_VERSION})",
            log.format_version
        )));
    }
    Ok(log)
}

/// Record that a bundle was proved, at `now` (unix seconds).
///
/// The **only** function in this module that writes to a vault directory, and
/// it is never reached from a verification path: the caller decides to record,
/// after deciding the bundle belongs to this vault. Re-verifying a bundle
/// replaces its row rather than appending a second one — the interesting fact
/// is when a copy was *last* proved.
///
/// A record file that cannot be read is not overwritten: an audit record worth
/// gating a `drop` on is worth refusing to silently replace.
pub fn record_verification(
    paths: &VaultPaths,
    entry: VerificationRecord,
    now: i64,
) -> Result<VerificationRecord> {
    if !paths.exists() {
        return Err(VaultError::NotInitialized(paths.root.clone()));
    }
    let mut log = read_verifications(paths)?;
    let entry = VerificationRecord {
        verified_at: now,
        ..entry
    };
    log.format_version = ESCROW_RECORD_FORMAT_VERSION;
    log.entries.retain(|e| e.bundle_blake3 != entry.bundle_blake3);
    log.entries.push(entry.clone());
    log.entries.sort_by_key(|e| e.verified_at);
    let excess = log.entries.len().saturating_sub(MAX_VERIFICATION_RECORDS);
    log.entries.drain(..excess);

    let mut text = String::from(RECORD_BANNER);
    text.push('\n');
    text.push_str(&toml::to_string_pretty(&log)?);
    storage::atomic_write_mode(&paths.escrow_record(), text.as_bytes(), 0o644)?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault-shaped directory holding exactly the files a test names. Export
    /// opens nothing, so a fixture needs no real keys and no Argon2 — the same
    /// trick `recovery_policy`'s tests use.
    fn fixture(files: &[(&str, &[u8])]) -> (tempfile::TempDir, VaultPaths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::for_garden(tmp.path());
        fs::create_dir_all(&paths.root).unwrap();
        for (name, bytes) in files {
            let p = paths.root.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, bytes).unwrap();
        }
        (tmp, paths)
    }

    fn minimal() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("params.toml", b"format_version = 1\n" as &[u8]),
            ("active.toml", b"master_key_id = 1\n"),
            ("k.self", b"eighty-eight-ish bytes of sealed K"),
            ("identity.key", b"sealed identity"),
            ("master/1.key", b"sealed master gen 1"),
        ]
    }

    #[test]
    fn export_refuses_a_directory_that_is_not_a_vault() {
        let (tmp, paths) = fixture(&[("active.toml", b"master_key_id = 1\n")]);
        let dest = tmp.path().join("escrow.toml");
        match export(&paths, None, &dest, false) {
            Err(VaultError::NotInitialized(_)) => {}
            other => panic!("expected NotInitialized, got {other:?}"),
        }
        assert!(!dest.exists(), "nothing should be written");
    }

    #[test]
    fn members_are_the_allowlist_in_canonical_order() {
        let mut files = minimal();
        files.push(("k.recovery", b"sealed K under the phrase"));
        files.push(("transport.key", b"sealed transport"));
        files.push(("master/2.key", b"sealed master gen 2"));
        files.push(("master/10.key", b"sealed master gen 10"));
        files.push(("shared-keys/b.key", b"sealed S b"));
        files.push(("shared-keys/a.key", b"sealed S a"));
        // Not key material, and famously living in the vault root: it must not
        // ride along. This is the property the allowlist exists for.
        files.push(("sealed-paths.toml", b"globs = [\"secret/**\"]"));
        let (tmp, paths) = fixture(&files);

        let dest = tmp.path().join("escrow.toml");
        let summary = export(&paths, None, &dest, false).unwrap();

        assert_eq!(
            summary.members,
            vec![
                "params.toml",
                "active.toml",
                "k.self",
                "k.recovery",
                "identity.key",
                "transport.key",
                // Numeric ascending, so 10 sorts after 2 rather than after 1.
                "master/1.key",
                "master/2.key",
                "master/10.key",
                "shared-keys/a.key",
                "shared-keys/b.key",
            ]
        );
        assert_eq!(summary.absent, vec!["recovery.toml"]);
        assert!(
            !summary.members.iter().any(|m| m == "sealed-paths.toml"),
            "a non-key file in the vault root must not be escrowed"
        );
    }

    #[test]
    fn two_exports_of_one_vault_are_byte_identical() {
        let (tmp, paths) = fixture(&minimal());
        let a = tmp.path().join("a.toml");
        let b = tmp.path().join("b.toml");

        let sa = export(&paths, Some("garden-1"), &a, false).unwrap();
        let sb = export(&paths, Some("garden-1"), &b, false).unwrap();

        assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
        assert_eq!(sa.bundle_blake3, sb.bundle_blake3);
    }

    #[test]
    fn bundle_is_written_at_0600_and_carries_each_members_mode() {
        let (tmp, paths) = fixture(&minimal());
        fs::set_permissions(paths.root.join("params.toml"), fs::Permissions::from_mode(0o644))
            .unwrap();
        fs::set_permissions(paths.root.join("k.self"), fs::Permissions::from_mode(0o600)).unwrap();

        let dest = tmp.path().join("escrow.toml");
        export(&paths, None, &dest, false).unwrap();

        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let bundle = parse(&fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(bundle.member("params.toml").unwrap().mode, "644");
        assert_eq!(bundle.member("k.self").unwrap().mode, "600");
        assert_eq!(bundle.member("k.self").unwrap().mode_bits().unwrap(), 0o600);
    }

    #[test]
    fn an_existing_different_bundle_is_refused_unless_forced() {
        let (tmp, paths) = fixture(&minimal());
        let dest = tmp.path().join("escrow.toml");
        fs::write(&dest, b"an older export").unwrap();

        match export(&paths, None, &dest, false) {
            Err(VaultError::EscrowTargetExists(p)) => assert_eq!(p, dest),
            other => panic!("expected EscrowTargetExists, got {other:?}"),
        }
        assert_eq!(fs::read(&dest).unwrap(), b"an older export");

        export(&paths, None, &dest, true).unwrap();
        assert!(fs::read_to_string(&dest).unwrap().contains("[[member]]"));
    }

    #[test]
    fn re_exporting_an_unchanged_vault_over_itself_is_not_a_conflict() {
        let (tmp, paths) = fixture(&minimal());
        let dest = tmp.path().join("escrow.toml");
        export(&paths, None, &dest, false).unwrap();
        // Same vault, same bytes: no --force needed, because nothing is lost.
        export(&paths, None, &dest, false).unwrap();
    }

    #[test]
    fn an_unlabelled_export_records_an_empty_garden_id() {
        let (tmp, paths) = fixture(&minimal());
        let dest = tmp.path().join("escrow.toml");
        let summary = export(&paths, None, &dest, false).unwrap();
        assert_eq!(summary.garden_id, "");

        let bundle = parse(&fs::read_to_string(&dest).unwrap()).unwrap();
        assert_eq!(bundle.garden_id, "");
    }

    #[test]
    fn the_banner_is_readable_plain_text_and_the_document_still_parses() {
        let (tmp, paths) = fixture(&minimal());
        let dest = tmp.path().join("escrow.toml");
        export(&paths, None, &dest, false).unwrap();

        let text = fs::read_to_string(&dest).unwrap();
        assert!(text.starts_with('#'), "the banner leads the file");
        assert!(text.contains("INERT WITHOUT THE"));
        assert!(text.contains("master passphrase"));
        // The banner is TOML comments, so the whole file is one document.
        parse(&text).unwrap();
    }

    #[test]
    fn a_bundle_from_a_newer_soft_fig_is_refused_by_version() {
        let (tmp, paths) = fixture(&minimal());
        let dest = tmp.path().join("escrow.toml");
        export(&paths, None, &dest, false).unwrap();
        let text = fs::read_to_string(&dest)
            .unwrap()
            .replace("format_version = 1", "format_version = 99");
        match parse(&text) {
            Err(VaultError::EscrowMalformed(msg)) => assert!(msg.contains("99")),
            other => panic!("expected EscrowMalformed, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 003 — verification. These exercise the structural half: what a bundle
    // says about itself, checked without a passphrase and without a vault.
    // -----------------------------------------------------------------------

    /// Export a fixture and read the file back as text, ready to be tampered
    /// with. Tampering the *text* rather than the struct is deliberate: it is
    /// what a failing SD card and a curious editor both actually do.
    fn exported(files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let (tmp, paths) = fixture(files);
        let dest = tmp.path().join("escrow.toml");
        export(&paths, Some("garden-1"), &dest, false).unwrap();
        let text = fs::read_to_string(&dest).unwrap();
        (tmp, text)
    }

    fn findings_of(text: &str) -> Vec<Finding> {
        check_integrity(&parse(text).unwrap()).findings
    }

    #[test]
    fn a_clean_bundle_reports_intact() {
        let (_tmp, text) = exported(&minimal());
        let report = check_integrity(&parse(&text).unwrap());
        assert!(report.is_intact(), "unexpected findings: {:?}", report.findings);
        assert_eq!(report.garden_id, "garden-1");
        assert_eq!(report.policy, "passphrase-only");
        assert!(report.undeclared_doors.is_empty());
        assert_eq!(
            report.self_blake3,
            blake3::hash(b"eighty-eight-ish bytes of sealed K").to_hex().to_string(),
            "the report hashes the k.self it actually carries, not the manifest's claim"
        );
    }

    #[test]
    fn one_flipped_byte_names_the_member_it_damaged() {
        let (_tmp, text) = exported(&minimal());
        // Flip a byte inside `identity.key`'s base64 payload.
        let target = B64.encode(b"sealed identity");
        let mut flipped = target.clone().into_bytes();
        flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
        let text = text.replace(&target, &String::from_utf8(flipped).unwrap());

        match findings_of(&text).as_slice() {
            [Finding::Corrupt { name, expected, actual }] => {
                assert_eq!(name, "identity.key");
                assert_ne!(expected, actual);
            }
            other => panic!("expected exactly one Corrupt finding, got {other:?}"),
        }
    }

    #[test]
    fn a_size_that_disagrees_with_the_bytes_is_its_own_finding() {
        let (_tmp, text) = exported(&minimal());
        // `identity.key` is the only 15-byte member in the fixture.
        let text = text.replace("size = 15", "size = 14");
        let findings = findings_of(&text);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                Finding::SizeMismatch { name, declared: 14, actual: 15 } if name == "identity.key"
            )),
            "got {findings:?}"
        );
    }

    #[test]
    fn a_member_name_outside_the_allowlist_is_refused() {
        // Path traversal is the case that matters: these names become paths on
        // a restore, so an escrow reader must reject them long before then.
        for name in ["../../etc/passwd", "master/../k.self", "notes.txt", "master/x.key"] {
            let (_tmp, text) = exported(&minimal());
            let text = text.replace("name = \"identity.key\"", &format!("name = {name:?}"));
            let findings = findings_of(&text);
            assert!(
                findings.iter().any(|f| matches!(f, Finding::Unknown { name: n } if n == name)),
                "{name} should be refused, got {findings:?}"
            );
        }
    }

    #[test]
    fn the_same_member_twice_is_reported() {
        let (_tmp, text) = exported(&minimal());
        let bundle = parse(&text).unwrap();
        let mut doubled = bundle.clone();
        doubled.members.push(bundle.members[0].clone());
        doubled.member_count += 1;

        let findings = check_integrity(&doubled).findings;
        assert!(
            findings.iter().any(|f| matches!(f, Finding::Duplicate { .. })),
            "got {findings:?}"
        );
    }

    #[test]
    fn a_member_count_that_lies_is_reported() {
        let (_tmp, text) = exported(&minimal());
        let mut bundle = parse(&text).unwrap();
        bundle.member_count = 99;
        let findings = check_integrity(&bundle).findings;
        assert!(
            findings.iter().any(|f| matches!(
                f,
                Finding::CountMismatch { declared: 99, actual: 5 }
            )),
            "got {findings:?}"
        );
    }

    #[test]
    fn a_bundle_missing_the_master_its_active_pointer_names_is_incomplete() {
        let mut files = minimal();
        files.retain(|(n, _)| *n != "master/1.key");
        let (_tmp, text) = exported(&files);
        let findings = findings_of(&text);
        assert!(
            findings.iter().any(|f| matches!(
                f,
                Finding::Missing { name, .. } if name == "master/1.key"
            )),
            "got {findings:?}"
        );
    }

    #[test]
    fn a_policy_that_claims_a_door_the_bundle_does_not_carry_fails() {
        let (_tmp, text) = exported(&minimal());
        // The vault has no `k.recovery`; claim one anyway. Per the slice this
        // is a FAILED verification, not a warning: the bundle is an escrow of
        // a recovery shape that does not exist.
        let text = text.replace(
            "policy = \"passphrase-only\"",
            "policy = \"passphrase+phrase\"",
        );
        match findings_of(&text).as_slice() {
            [Finding::MissingDoor { path, location }] => {
                assert_eq!(path, "phrase");
                assert_eq!(location, "k.recovery");
            }
            other => panic!("expected one MissingDoor, got {other:?}"),
        }
    }

    #[test]
    fn a_door_the_policy_does_not_mention_is_surfaced_but_does_not_fail() {
        let mut files = minimal();
        files.push(("k.recovery", b"sealed K under the phrase"));
        let (_tmp, text) = exported(&files);
        let text = text.replace(
            "policy = \"passphrase+phrase\"",
            "policy = \"passphrase-only\"",
        );

        let report = check_integrity(&parse(&text).unwrap());
        assert!(report.is_intact(), "an extra door is not a gap: {:?}", report.findings);
        assert_eq!(report.undeclared_doors, vec!["phrase"]);
    }

    #[test]
    fn a_truncated_bundle_fails_to_parse_rather_than_panicking() {
        let (_tmp, text) = exported(&minimal());
        for cut in [text.len() / 2, text.len() - 10, BANNER.len() + 4] {
            assert!(
                parse(&text[..cut]).is_err(),
                "a bundle cut at {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn the_verification_record_never_rides_the_bundle() {
        // It must not: a bundle that changed every time it was verified would
        // lose the determinism that lets copies be compared by hash — and
        // would make verifying a copy invalidate the copy.
        let mut files = minimal();
        files.push((storage::ESCROW_RECORD_FILE, b"format_version = 1\n"));
        let (tmp, paths) = fixture(&files);

        let a = tmp.path().join("a.toml");
        let summary = export(&paths, None, &a, false).unwrap();
        assert!(
            !summary.members.iter().any(|m| m == storage::ESCROW_RECORD_FILE),
            "the verification record is not key material and must not be escrowed"
        );
        assert!(!member_name_is_known(storage::ESCROW_RECORD_FILE));
    }

    #[test]
    fn re_verifying_one_bundle_replaces_its_row_rather_than_appending() {
        let (_tmp, paths) = fixture(&minimal());
        let entry = VerificationRecord {
            bundle_blake3: "aaaa".into(),
            self_blake3: "bbbb".into(),
            garden_id: "garden-1".into(),
            policy: "passphrase-only".into(),
            member_count: 5,
            outcome: OUTCOME_OPENABLE.into(),
            verified_at: 0,
        };
        record_verification(&paths, entry.clone(), 1_000).unwrap();
        record_verification(&paths, entry, 2_000).unwrap();

        let log = read_verifications(&paths).unwrap();
        assert_eq!(log.entries.len(), 1, "same bundle, one row");
        assert_eq!(log.latest().unwrap().verified_at, 2_000);
    }

    #[test]
    fn the_record_keeps_the_newest_verifications_and_drops_the_oldest() {
        let (_tmp, paths) = fixture(&minimal());
        for i in 0..(MAX_VERIFICATION_RECORDS as i64 + 5) {
            let entry = VerificationRecord {
                bundle_blake3: format!("bundle-{i}"),
                self_blake3: "bbbb".into(),
                garden_id: "garden-1".into(),
                policy: "passphrase-only".into(),
                member_count: 5,
                outcome: OUTCOME_OPENABLE.into(),
                verified_at: 0,
            };
            record_verification(&paths, entry, 1_000 + i).unwrap();
        }
        let log = read_verifications(&paths).unwrap();
        assert_eq!(log.entries.len(), MAX_VERIFICATION_RECORDS);
        assert!(log.verified("bundle-0").is_none(), "the oldest rows age out");
        assert!(log.verified("bundle-20").is_some(), "the newest is kept");
    }

    #[test]
    fn a_record_file_that_cannot_be_read_is_never_silently_replaced() {
        let (_tmp, paths) = fixture(&minimal());
        fs::write(paths.escrow_record(), b"this is not toml {{{").unwrap();
        let entry = VerificationRecord {
            bundle_blake3: "aaaa".into(),
            self_blake3: "bbbb".into(),
            garden_id: "garden-1".into(),
            policy: "passphrase-only".into(),
            member_count: 5,
            outcome: OUTCOME_OPENABLE.into(),
            verified_at: 0,
        };
        assert!(record_verification(&paths, entry, 1_000).is_err());
        assert_eq!(
            fs::read(paths.escrow_record()).unwrap(),
            b"this is not toml {{{",
            "an audit record worth gating a drop on is worth refusing to overwrite"
        );
    }

}
