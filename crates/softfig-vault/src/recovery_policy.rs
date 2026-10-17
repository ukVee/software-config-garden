//! The **declared** recovery shape of a garden, and an honest read of the
//! wrappings actually on disk.
//!
//! # Why a declaration exists at all
//!
//! A vault that records only *what wrappings exist* can never report that
//! something is wrong, because whatever exists is by definition what exists.
//! Recording the human's **intent** separately is what turns "you have one
//! wrapping" into "you have one wrapping and you meant to have two" — the
//! second is actionable, the first is a shrug. The gap between the declaration
//! and the disk is the entire product of this module. See
//! `journal/decisions/decision-vault-recovery-policy.md` in the garden.
//!
//! # Nothing here opens a wrapping
//!
//! Enumeration is file presence and nothing more. No passphrase is taken, no
//! `unwrap_kek_*` is called, no [`crate::kek::Kek`] is constructed — none of
//! these functions can, since none of them accept a secret. That is what keeps
//! `vault status` usable on a **locked** vault: observing costs nothing.
//! Proving that a wrapping actually *opens* is a separate, explicit verb
//! against an escrow bundle. **`status` observes; `verify` proves.**
//!
//! # Migration
//!
//! A vault with no declaration is not broken. It reports as
//! [`DeclaredPolicy::Undeclared`], its shape is *inferred* from the wrappings
//! present, and the operator is prompted to declare. Nothing in this module
//! writes a declaration on the user's behalf — inventing one would erase the
//! very divergence the declaration exists to expose.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::storage::{self, VaultPaths};

/// On-disk schema version for `recovery.toml`. Independent of
/// [`crate::params::CURRENT_FORMAT_VERSION`] on purpose: the declaration is
/// non-secret annotation and must be able to change shape without touching the
/// params that gate every unlock.
pub const RECOVERY_POLICY_FORMAT_VERSION: u32 = 1;

/// One door into `K`.
///
/// The three the vault knows about. Ordering is the canonical rendering order
/// (`passphrase+phrase+peers`), so a `BTreeSet` of these displays consistently
/// without a sort at each call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecoveryPath {
    /// The master passphrase, Argon2id-wrapped at `k.self`.
    Passphrase,
    /// The printed recovery phrase, Argon2id-wrapped at `k.recovery`.
    Phrase,
    /// Peer-path wrappings under the trust matrix. **Spec, not code** — see
    /// [`crate::storage::PEER_KEKS_DIR`]. Declaring this today is legal and
    /// will honestly report as a promised-but-absent door.
    Peers,
}

impl RecoveryPath {
    /// Every path, in canonical order. Iterating this (rather than a set) is
    /// what makes divergence reporting deterministic.
    pub const ALL: [RecoveryPath; 3] = [Self::Passphrase, Self::Phrase, Self::Peers];

    /// The token used in the policy string and on the wire.
    pub fn token(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::Phrase => "phrase",
            Self::Peers => "peers",
        }
    }

    /// The single path named by this token, if it names one. `RecoveryPolicy`
    /// parses whole shapes (`passphrase+phrase`); this parses one door, which
    /// is what `recovery add` / `recovery drop` take.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        Self::ALL.into_iter().find(|p| p.token() == s)
    }

    /// Where this door lives inside the vault directory. Operator-facing: a
    /// divergence is far more actionable when it names the file.
    pub fn location(self) -> &'static str {
        match self {
            Self::Passphrase => storage::KEK_SELF_FILE,
            Self::Phrase => storage::KEK_RECOVERY_FILE,
            Self::Peers => storage::PEER_KEKS_DIR,
        }
    }
}

impl fmt::Display for RecoveryPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// A set of [`RecoveryPath`]s — the shape of a garden's recovery.
///
/// Deliberately a plain set with no mandatory member. Every shape declarable
/// today includes [`RecoveryPath::Passphrase`], but forcing it into the type
/// would make the two states this milestone must be able to *describe*
/// unrepresentable: a vault whose self-path has been dropped in favour of
/// another door, and a vault with no door at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryPolicy {
    paths: BTreeSet<RecoveryPath>,
}

impl RecoveryPolicy {
    pub fn new(paths: impl IntoIterator<Item = RecoveryPath>) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

    /// The mode this milestone exists to make first-class: one door, the
    /// master passphrase, and an escrow copy of the 88 bytes it opens.
    pub fn passphrase_only() -> Self {
        Self::new([RecoveryPath::Passphrase])
    }

    pub fn contains(&self, path: RecoveryPath) -> bool {
        self.paths.contains(&path)
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// Canonical order.
    pub fn paths(&self) -> impl Iterator<Item = RecoveryPath> + '_ {
        self.paths.iter().copied()
    }

    pub fn insert(&mut self, path: RecoveryPath) -> bool {
        self.paths.insert(path)
    }

    pub fn remove(&mut self, path: RecoveryPath) -> bool {
        self.paths.remove(&path)
    }
}

impl fmt::Display for RecoveryPolicy {
    /// `passphrase-only` | `passphrase+phrase` | `passphrase+peers` |
    /// `passphrase+phrase+peers` | `none`. Round-trips through
    /// [`RecoveryPolicy::parse`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.paths.is_empty() {
            return f.write_str(NONE_TOKEN);
        }
        if self.paths.len() == 1 && self.contains(RecoveryPath::Passphrase) {
            return f.write_str(PASSPHRASE_ONLY_TOKEN);
        }
        let mut first = true;
        for path in self.paths() {
            if !first {
                f.write_str("+")?;
            }
            f.write_str(path.token())?;
            first = false;
        }
        Ok(())
    }
}

const NONE_TOKEN: &str = "none";
const PASSPHRASE_ONLY_TOKEN: &str = "passphrase-only";

/// A policy string that named something the vault does not recognise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsePolicyError {
    /// The offending fragment, verbatim, so the operator can see their typo.
    pub token: String,
}

impl fmt::Display for ParsePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unrecognized recovery path {:?} (expected {}, {}, {}, {}, or a '+'-joined combination)",
            self.token,
            PASSPHRASE_ONLY_TOKEN,
            RecoveryPath::Passphrase.token(),
            RecoveryPath::Phrase.token(),
            RecoveryPath::Peers.token(),
        )
    }
}

impl std::error::Error for ParsePolicyError {}

impl RecoveryPolicy {
    /// Parse the canonical form, plus two spellings a human will reasonably
    /// type: bare `passphrase` for `passphrase-only`, and any ordering of the
    /// `+`-joined tokens.
    pub fn parse(s: &str) -> std::result::Result<Self, ParsePolicyError> {
        let trimmed = s.trim().to_ascii_lowercase();
        if trimmed == NONE_TOKEN {
            return Ok(Self::default());
        }
        if trimmed == PASSPHRASE_ONLY_TOKEN {
            return Ok(Self::passphrase_only());
        }
        let mut paths = BTreeSet::new();
        for raw in trimmed.split('+') {
            let token = raw.trim();
            let path = RecoveryPath::ALL
                .iter()
                .copied()
                .find(|p| p.token() == token)
                .ok_or_else(|| ParsePolicyError {
                    token: token.to_string(),
                })?;
            paths.insert(path);
        }
        Ok(Self { paths })
    }
}

impl std::str::FromStr for RecoveryPolicy {
    type Err = ParsePolicyError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// The literal contents of `recovery.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryPolicyFile {
    format_version: u32,
    policy: String,
}

/// What `recovery.toml` yielded. All three are reportable states; none is an
/// error, because `vault status` must never fail on the way to telling the
/// operator what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclaredPolicy {
    /// A declaration, parsed.
    Declared(RecoveryPolicy),
    /// No `recovery.toml`. The garden predates the declaration, or its owner
    /// has not declared yet.
    Undeclared,
    /// A `recovery.toml` that exists but could not be read as a declaration:
    /// unreadable, malformed, or written by a newer soft-fig. The vault
    /// degrades to *inferred* and says why — it does not refuse to report.
    Unreadable(String),
}

impl DeclaredPolicy {
    pub fn declared(&self) -> Option<&RecoveryPolicy> {
        match self {
            Self::Declared(p) => Some(p),
            _ => None,
        }
    }
}

/// Read the declaration. Infallible by construction — every failure is a
/// [`DeclaredPolicy::Unreadable`] carrying its reason.
pub fn load_declared_policy(paths: &VaultPaths) -> DeclaredPolicy {
    let path = paths.recovery_policy();
    if !path.exists() {
        return DeclaredPolicy::Undeclared;
    }
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) => return DeclaredPolicy::Unreadable(format!("could not read: {e}")),
    };
    let file: RecoveryPolicyFile = match toml::from_str(&raw) {
        Ok(file) => file,
        Err(e) => return DeclaredPolicy::Unreadable(format!("malformed TOML: {e}")),
    };
    if file.format_version != RECOVERY_POLICY_FORMAT_VERSION {
        return DeclaredPolicy::Unreadable(format!(
            "format version {} is newer than this soft-fig understands ({})",
            file.format_version, RECOVERY_POLICY_FORMAT_VERSION
        ));
    }
    match RecoveryPolicy::parse(&file.policy) {
        Ok(policy) => DeclaredPolicy::Declared(policy),
        Err(e) => DeclaredPolicy::Unreadable(e.to_string()),
    }
}

/// Persist a declaration. The only writer in this module, and it is never
/// called on the user's behalf — only from a verb where the operator said what
/// they intend.
///
/// Published at `0644` like the other plaintext vault metadata: the
/// declaration names which doors exist, never what is behind them.
pub fn store_declared_policy(paths: &VaultPaths, policy: &RecoveryPolicy) -> Result<()> {
    let file = RecoveryPolicyFile {
        format_version: RECOVERY_POLICY_FORMAT_VERSION,
        policy: policy.to_string(),
    };
    let raw = toml::to_string_pretty(&file)?;
    storage::atomic_write_mode(&paths.recovery_policy(), raw.as_bytes(), 0o644)
}

/// The wrappings of `K` actually present in the vault directory.
///
/// Presence only. Constructing this takes no secret and opens nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wrappings {
    /// `k.self` is on disk.
    pub passphrase: bool,
    /// `k.recovery` is on disk.
    pub phrase: bool,
    /// Peer ids with a wrapping under `peer-keks/`, sorted. Always empty
    /// today — the peer path is unimplemented.
    pub peers: Vec<String>,
}

impl Wrappings {
    /// Enumerate from disk. Infallible: an unreadable vault directory reports
    /// as "nothing found", which is itself the most important thing status can
    /// say.
    pub fn read(paths: &VaultPaths) -> Self {
        Self {
            passphrase: paths.kek_self().exists(),
            phrase: paths.kek_recovery().exists(),
            peers: storage::list_peer_kek_ids(paths),
        }
    }

    pub fn contains(&self, path: RecoveryPath) -> bool {
        match path {
            RecoveryPath::Passphrase => self.passphrase,
            RecoveryPath::Phrase => self.phrase,
            RecoveryPath::Peers => !self.peers.is_empty(),
        }
    }

    /// The shape these wrappings imply — the policy a vault would be assigned
    /// if intent were read off the filesystem. Used only where no declaration
    /// exists, and always reported as *inferred*.
    pub fn as_policy(&self) -> RecoveryPolicy {
        RecoveryPolicy::new(
            RecoveryPath::ALL
                .into_iter()
                .filter(|p| self.contains(*p)),
        )
    }

    /// How many doors are actually on disk. One is the number this whole
    /// milestone was written about.
    pub fn count(&self) -> usize {
        usize::from(self.passphrase) + usize::from(self.phrase) + self.peers.len()
    }
}

/// A mismatch between what was declared and what is on disk. Both directions
/// are states to report, not errors to raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Divergence {
    /// Declared, but no such wrapping exists — a door that was promised and
    /// isn't there.
    Promised(RecoveryPath),
    /// On disk, but not declared — an undeclared door. Each one is an
    /// independent way into the garden that its owner has not accounted for.
    Undeclared(RecoveryPath),
}

impl Divergence {
    pub fn path(self) -> RecoveryPath {
        match self {
            Self::Promised(p) | Self::Undeclared(p) => p,
        }
    }
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promised(p) => write!(
                f,
                "'{}' is declared but {} is not on disk",
                p.token(),
                p.location()
            ),
            Self::Undeclared(p) => write!(
                f,
                "{} is on disk but '{}' is not declared",
                p.location(),
                p.token()
            ),
        }
    }
}

/// Everything `vault status` needs to tell the truth about recovery: the
/// declaration, the disk, and the gap between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub declared: DeclaredPolicy,
    pub wrappings: Wrappings,
    /// Empty when the policy is inferred — inference reads the disk, so it can
    /// never disagree with it. A divergence is only meaningful against a
    /// declaration.
    pub divergences: Vec<Divergence>,
}

impl RecoveryStatus {
    /// Read the whole picture. Takes no secret and opens no wrapping.
    pub fn read(paths: &VaultPaths) -> Self {
        let declared = load_declared_policy(paths);
        let wrappings = Wrappings::read(paths);
        let divergences = match declared.declared() {
            Some(policy) => diverge(policy, &wrappings),
            None => Vec::new(),
        };
        Self {
            declared,
            wrappings,
            divergences,
        }
    }

    /// The policy to report: the declaration if there is one, otherwise what
    /// the wrappings imply. Pair with [`Self::is_inferred`] — reporting an
    /// inferred shape as though it were declared is exactly the silence this
    /// module exists to break.
    pub fn effective(&self) -> RecoveryPolicy {
        match self.declared.declared() {
            Some(policy) => policy.clone(),
            None => self.wrappings.as_policy(),
        }
    }

    /// True when the reported shape was read off the disk rather than stated
    /// by a human.
    pub fn is_inferred(&self) -> bool {
        self.declared.declared().is_none()
    }
}

/// Both directions of divergence, in canonical path order.
fn diverge(policy: &RecoveryPolicy, wrappings: &Wrappings) -> Vec<Divergence> {
    let mut out = Vec::new();
    for path in RecoveryPath::ALL {
        match (policy.contains(path), wrappings.contains(path)) {
            (true, false) => out.push(Divergence::Promised(path)),
            (false, true) => out.push(Divergence::Undeclared(path)),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vault directory with only the files a test asks for. No keys, no
    /// Argon2 — enumeration reads presence, so presence is all a fixture needs.
    fn fixture(files: &[&str]) -> (tempfile::TempDir, VaultPaths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = VaultPaths::for_garden(tmp.path());
        fs::create_dir_all(&paths.root).unwrap();
        for f in files {
            let p = paths.root.join(f);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, b"not a real wrapping").unwrap();
        }
        (tmp, paths)
    }

    #[test]
    fn every_policy_variant_round_trips_through_display_and_parse() {
        use RecoveryPath::*;
        let cases = [
            (RecoveryPolicy::default(), "none"),
            (RecoveryPolicy::passphrase_only(), "passphrase-only"),
            (RecoveryPolicy::new([Passphrase, Phrase]), "passphrase+phrase"),
            (RecoveryPolicy::new([Passphrase, Peers]), "passphrase+peers"),
            (
                RecoveryPolicy::new([Passphrase, Phrase, Peers]),
                "passphrase+phrase+peers",
            ),
            (RecoveryPolicy::new([Phrase]), "phrase"),
        ];
        for (policy, canonical) in cases {
            assert_eq!(policy.to_string(), canonical, "display of {policy:?}");
            assert_eq!(
                RecoveryPolicy::parse(canonical).unwrap(),
                policy,
                "parse of {canonical}"
            );
        }
    }

    #[test]
    fn parse_accepts_the_spellings_a_human_will_type() {
        assert_eq!(
            RecoveryPolicy::parse("  PASSPHRASE-ONLY ").unwrap(),
            RecoveryPolicy::passphrase_only()
        );
        // Bare `passphrase` is the same set as `passphrase-only`; the canonical
        // form is what comes back out.
        assert_eq!(
            RecoveryPolicy::parse("passphrase").unwrap().to_string(),
            "passphrase-only"
        );
        // Order in, canonical order out.
        assert_eq!(
            RecoveryPolicy::parse("peers + phrase+passphrase")
                .unwrap()
                .to_string(),
            "passphrase+phrase+peers"
        );
    }

    #[test]
    fn parse_names_the_offending_token() {
        let err = RecoveryPolicy::parse("passphrase+yubikey").unwrap_err();
        assert_eq!(err.token, "yubikey");
        assert!(err.to_string().contains("yubikey"), "{err}");
    }

    #[test]
    fn every_policy_variant_round_trips_through_the_persisted_file() {
        use RecoveryPath::*;
        for policy in [
            RecoveryPolicy::passphrase_only(),
            RecoveryPolicy::new([Passphrase, Phrase]),
            RecoveryPolicy::new([Passphrase, Peers]),
            RecoveryPolicy::new([Passphrase, Phrase, Peers]),
        ] {
            let (_tmp, paths) = fixture(&[]);
            store_declared_policy(&paths, &policy).unwrap();
            assert_eq!(
                load_declared_policy(&paths),
                DeclaredPolicy::Declared(policy.clone()),
                "round trip of {policy}"
            );
        }
    }

    #[test]
    fn enumeration_reports_a_vault_with_only_the_self_path() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE]);
        let w = Wrappings::read(&paths);
        assert!(w.passphrase);
        assert!(!w.phrase);
        assert!(w.peers.is_empty());
        assert_eq!(w.count(), 1);
        assert_eq!(w.as_policy().to_string(), "passphrase-only");
    }

    #[test]
    fn enumeration_reports_a_vault_with_both_wrappings() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE, storage::KEK_RECOVERY_FILE]);
        let w = Wrappings::read(&paths);
        assert!(w.passphrase && w.phrase);
        assert_eq!(w.count(), 2);
        assert_eq!(w.as_policy().to_string(), "passphrase+phrase");
    }

    #[test]
    fn enumeration_lists_peer_wrappings_sorted_and_ignores_other_files() {
        let (_tmp, paths) = fixture(&[
            storage::KEK_SELF_FILE,
            "peer-keks/tablet.key",
            "peer-keks/laptop.key",
            // Not a wrapping: no `.key` suffix. Enumerating it would invent a
            // door that does not exist.
            "peer-keks/README",
        ]);
        let w = Wrappings::read(&paths);
        assert_eq!(w.peers, vec!["laptop".to_string(), "tablet".to_string()]);
        assert_eq!(w.as_policy().to_string(), "passphrase+peers");
    }

    #[test]
    fn an_undeclared_vault_is_inferred_not_declared() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE, storage::KEK_RECOVERY_FILE]);
        let st = RecoveryStatus::read(&paths);
        assert_eq!(st.declared, DeclaredPolicy::Undeclared);
        assert!(st.is_inferred());
        assert_eq!(st.effective().to_string(), "passphrase+phrase");
        // Inference reads the disk, so it cannot disagree with it.
        assert!(st.divergences.is_empty());
        // And nothing was written on the user's behalf.
        assert!(!paths.recovery_policy().exists());
    }

    #[test]
    fn a_promised_door_that_is_not_there_is_reported() {
        // Declared passphrase+phrase, but k.recovery was never written.
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE]);
        store_declared_policy(
            &paths,
            &RecoveryPolicy::new([RecoveryPath::Passphrase, RecoveryPath::Phrase]),
        )
        .unwrap();
        let st = RecoveryStatus::read(&paths);
        assert!(!st.is_inferred());
        assert_eq!(
            st.divergences,
            vec![Divergence::Promised(RecoveryPath::Phrase)]
        );
        assert!(
            st.divergences[0].to_string().contains("k.recovery"),
            "divergence must name the file: {}",
            st.divergences[0]
        );
    }

    #[test]
    fn an_undeclared_door_that_is_there_is_reported() {
        // This device's own state on 2026-09-06: passphrase-only in intent,
        // k.recovery still on disk under a phrase nobody has.
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE, storage::KEK_RECOVERY_FILE]);
        store_declared_policy(&paths, &RecoveryPolicy::passphrase_only()).unwrap();
        let st = RecoveryStatus::read(&paths);
        assert_eq!(
            st.divergences,
            vec![Divergence::Undeclared(RecoveryPath::Phrase)]
        );
    }

    #[test]
    fn both_divergence_directions_are_reported_together_in_canonical_order() {
        // Declared phrase (absent) while peers (present) go undeclared.
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE, "peer-keks/server.key"]);
        store_declared_policy(
            &paths,
            &RecoveryPolicy::new([RecoveryPath::Passphrase, RecoveryPath::Phrase]),
        )
        .unwrap();
        let st = RecoveryStatus::read(&paths);
        assert_eq!(
            st.divergences,
            vec![
                Divergence::Promised(RecoveryPath::Phrase),
                Divergence::Undeclared(RecoveryPath::Peers),
            ]
        );
        // Rendered, not just detected: each line has to say which direction it
        // is and where to look, or the operator learns nothing actionable.
        let rendered: Vec<String> = st.divergences.iter().map(|d| d.to_string()).collect();
        assert_eq!(
            rendered,
            vec![
                "'phrase' is declared but k.recovery is not on disk".to_string(),
                "peer-keks is on disk but 'peers' is not declared".to_string(),
            ]
        );
    }

    #[test]
    fn a_declaration_matching_the_disk_diverges_not_at_all() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE, storage::KEK_RECOVERY_FILE]);
        store_declared_policy(
            &paths,
            &RecoveryPolicy::new([RecoveryPath::Passphrase, RecoveryPath::Phrase]),
        )
        .unwrap();
        assert!(RecoveryStatus::read(&paths).divergences.is_empty());
    }

    #[test]
    fn an_unparseable_declaration_degrades_to_inferred_with_a_reason() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE]);
        fs::write(paths.recovery_policy(), b"this is not toml {{{").unwrap();
        let st = RecoveryStatus::read(&paths);
        match &st.declared {
            DeclaredPolicy::Unreadable(reason) => assert!(
                reason.contains("malformed TOML"),
                "reason should say what went wrong: {reason}"
            ),
            other => panic!("expected Unreadable, got {other:?}"),
        }
        // Degraded, not failed: status still reports a shape.
        assert!(st.is_inferred());
        assert_eq!(st.effective().to_string(), "passphrase-only");
    }

    #[test]
    fn a_declaration_naming_an_unknown_door_degrades_to_inferred() {
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE]);
        fs::write(
            paths.recovery_policy(),
            b"format_version = 1\npolicy = \"passphrase+smartcard\"\n",
        )
        .unwrap();
        let st = RecoveryStatus::read(&paths);
        match &st.declared {
            DeclaredPolicy::Unreadable(reason) => {
                assert!(reason.contains("smartcard"), "{reason}")
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert!(st.is_inferred());
    }

    #[test]
    fn a_newer_format_version_degrades_instead_of_being_misread() {
        // A future soft-fig may add fields this build would silently ignore.
        // Reporting "I can't read this" beats reporting a half-understood
        // declaration as fact.
        let (_tmp, paths) = fixture(&[storage::KEK_SELF_FILE]);
        fs::write(
            paths.recovery_policy(),
            b"format_version = 99\npolicy = \"passphrase-only\"\n",
        )
        .unwrap();
        let st = RecoveryStatus::read(&paths);
        match &st.declared {
            DeclaredPolicy::Unreadable(reason) => assert!(reason.contains("99"), "{reason}"),
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert!(st.is_inferred());
    }

    #[test]
    fn a_vault_with_no_wrappings_at_all_is_representable() {
        // The catastrophic state. It must render, not panic or round to
        // "passphrase-only".
        let (_tmp, paths) = fixture(&[]);
        let st = RecoveryStatus::read(&paths);
        assert_eq!(st.wrappings.count(), 0);
        assert_eq!(st.effective().to_string(), "none");
    }
}
