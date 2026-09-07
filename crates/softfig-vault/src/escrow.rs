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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};
use crate::recovery_policy::{DeclaredPolicy, RecoveryStatus};
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
    let bundle_blake3 = blake3::hash(&bytes).to_hex().to_string();

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
/// the format version; proving the members actually open is `escrow verify`'s
/// job, which extends this.
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
}
