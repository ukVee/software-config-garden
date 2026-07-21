//! The shared-subtree allow-list — the router's config source of truth
//! (M5c slice 003, [[decision-softfig-shared-subtrees-impl]] picks 2 + 3).
//!
//! Two files, two axes, deliberately split (mirrors the peers ring's
//! membership/endpoint split, `net.rs` 2026-06-15):
//!
//! * **`config/shared-subtrees.toml`** — the committed, ring-signed (m5d),
//!   encrypted, versioned **membership** allow-list. Each `[[subtree]]` carries
//!   the stable `id`, **this device's** `mount_path` (placement is per-device
//!   state — [[decision-shared-subtree-recipient-placement]]), the `refs`-table
//!   `ref_name` that holds the chain's tip, an optional `key_id` (a
//!   placeholder until m5d's collaborative `S` key), and the sharer's advisory
//!   `recommended_path` (m5f slice 002). Add/remove edit this file
//!   under a ring proposal (the key ceremony is a stubbed hook in m5c).
//!
//! * **`.softfig/shared-subtrees-local.toml`** — a per-device, **never
//!   committed** sidecar naming the subtree ids disabled on *this* device. This
//!   is what makes enable/disable a **local toggle with no ceremony and no
//!   membership change** ([[decision-softfig-shared-subtrees-impl]] pick 3): a
//!   disable writes only the sidecar, so it can never dirty the ring-signed
//!   membership nor perturb other members. Absence ⇒ every member is enabled.
//!
//! [`ChainRegistry::from_shared_config`] merges the two into the live registry;
//! an **empty** membership yields exactly [`ChainRegistry::device_only`], so the
//! whole feature is additive and off-by-default (byte-identical to today).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::chain::{Chain, ChainRegistry};

/// The committed membership filename (lives under `config/`, composed by the
/// daemon with its `CONFIG_DIR`).
pub const SHARED_SUBTREES_FILE: &str = "shared-subtrees.toml";

/// The per-device local-toggle sidecar filename (lives under `.softfig/`, next
/// to the peers-endpoint cache; never committed).
pub const LOCAL_TOGGLES_FILE: &str = "shared-subtrees-local.toml";

/// Garden dirs that are inherently machine-specific and must never be shared
/// across devices (the `spec-sync.md` safety denylist). Rejected at add-time.
pub const MACHINE_DIRS: &[&str] = &["hardware", "services", "os", "storage", "snapshots"];

/// Top-level garden names the daemon *trusts or writes as a matter of course*,
/// rejected at add-time alongside [`MACHINE_DIRS`] (slice 007, interim-review
/// finding 8 — the spec's denylist ellipsis is non-exhaustive by intent):
///
/// * `config` — the ring/daemon config home (`peers.toml`, `keeper.toml`,
///   `shared-subtrees.toml` itself). Grafting a shared chain here would let a
///   peer rewrite this device's trust ring and allow-list — it blinds the
///   loaders that every security decision reads from.
/// * `growlight` — daemon-managed queue machinery (`.seq` counters, the
///   managed queue table) that two devices' daemons would corrupt by turns,
///   and `protocol.md` is injected verbatim into agent sessions (an injection
///   surface if peer-writable).
/// * `journal` / `inbox` — the daemon's own verbs (`log_decision`,
///   `log_incident`, `archive`) and the documented triage flow write here
///   unconditionally; sharing them would silently route device-private
///   content into a peer-visible chain. Denying now is the safe v1 — relaxing
///   later is non-breaking, the reverse is not.
///
/// First-component match only: `projects/app/config` is ordinary content.
pub const RESERVED_TOP_DIRS: &[&str] = &["config", "growlight", "journal", "inbox"];

/// Infrastructure names rejected at **any** path depth (slice 007): `.softfig`
/// (the VCS/vault state namespace), `.claude` (the agent harness executes
/// hooks/settings found here), and `.softfigignore` (controls what the VCS
/// excludes). These names are infrastructure wherever they appear, so unlike
/// [`RESERVED_TOP_DIRS`] the check is per-component.
pub const INFRA_NAMES: &[&str] = &[".softfig", ".claude", ".softfigignore"];

/// The committed allow-list (`config/shared-subtrees.toml`). Ring-signed +
/// encrypted at rest in the garden; the `#[serde(rename)]` maps the array to
/// TOML `[[subtree]]` tables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSubtreesConfig {
    #[serde(default, rename = "subtree")]
    pub subtrees: Vec<SharedSubtreeEntry>,
}

/// One shared-subtree membership row. `enabled` is deliberately **absent** — the
/// on/off state is per-device and lives in [`LocalToggles`], not here.
///
/// The cross-member contract for a share is its *identity* — `{id, ref_name,
/// key_id, members}` — plus the advisory `recommended_path`; **placement is
/// per-device state** ([[decision-shared-subtree-recipient-placement]]). Each
/// device authors its own row, so `mount_path` here is *this device's* choice
/// and two members' rows for one chain may legitimately differ in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedSubtreeEntry {
    /// Stable id, assigned at add-time (the ring proposal). Keys the local toggle.
    pub id: String,
    /// **This device's** placement: the garden-relative mount prefix
    /// (`/`-separated, e.g. `projects/journals`) where *this* device projects
    /// the chain. Per-device state — never ring-agreed, never on the wire; other
    /// members may mount the same chain elsewhere.
    pub mount_path: String,
    /// The `refs`-table ref holding this chain's tip.
    pub ref_name: String,
    /// The collaborative key id — a placeholder (`None`) until m5d.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The sharer's advisory placement recommendation, set at share time and
    /// kept in the committed row so a late-joining device still sees it.
    /// Advisory ONLY — the accept default, never validated against and never
    /// authoritative; `mount_path` is what this device actually chose. Absent
    /// on pre-placement rows (m5f slice 002 added it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_path: Option<String>,
}

/// The per-device local-toggle sidecar (`.softfig/shared-subtrees-local.toml`).
/// Names the subtree ids disabled on *this* device; anything not listed (and any
/// absent file) is enabled.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalToggles {
    #[serde(default)]
    pub disabled: Vec<String>,
}

/// Unknown-field-tolerant mirrors of the membership schema, for
/// [`SharedSubtreesConfig::from_toml_str_lenient`]. Rows still require the
/// fields this version understands (a row missing `id`/`mount_path`/`ref_name`
/// is corrupt, not newer).
#[derive(Deserialize)]
struct LenientSubtrees {
    #[serde(default, rename = "subtree")]
    subtrees: Vec<LenientEntry>,
}

#[derive(Deserialize)]
struct LenientEntry {
    id: String,
    mount_path: String,
    ref_name: String,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    recommended_path: Option<String>,
}

impl SharedSubtreesConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Parse tolerating unknown fields — the **read/compose** path (registry
    /// derivation, `list`, toggle membership checks), so a newer-schema file
    /// with additive fields still composes what this version understands.
    /// Mutations must keep the strict [`Self::from_toml_str`]: a rewrite is
    /// only safe when every field is understood, else re-serializing would
    /// silently drop the fields this version doesn't know (slice 007,
    /// interim-review finding 5).
    pub fn from_toml_str_lenient(s: &str) -> Result<Self, toml::de::Error> {
        let lenient: LenientSubtrees = toml::from_str(s)?;
        Ok(Self {
            subtrees: lenient
                .subtrees
                .into_iter()
                .map(|e| SharedSubtreeEntry {
                    id: e.id,
                    mount_path: e.mount_path,
                    ref_name: e.ref_name,
                    key_id: e.key_id,
                    recommended_path: e.recommended_path,
                })
                .collect(),
        })
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Whether a subtree with this id is a member.
    pub fn contains(&self, id: &str) -> bool {
        self.subtrees.iter().any(|s| s.id == id)
    }
}

impl LocalToggles {
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn is_disabled(&self, id: &str) -> bool {
        self.disabled.iter().any(|d| d == id)
    }

    /// Mark `id` disabled on this device (idempotent). Returns whether it changed.
    pub fn disable(&mut self, id: &str) -> bool {
        if self.is_disabled(id) {
            false
        } else {
            self.disabled.push(id.to_string());
            true
        }
    }

    /// Clear a disable (idempotent). Returns whether it changed.
    pub fn enable(&mut self, id: &str) -> bool {
        let before = self.disabled.len();
        self.disabled.retain(|d| d != id);
        self.disabled.len() != before
    }
}

/// Why a proposed `mount_path` cannot be added as a shared subtree (add-time
/// validation, [[decision-softfig-shared-subtrees-impl]] design lock 2026-07-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareValidationError {
    /// The path is empty, absolute, or contains `..` — not a clean
    /// garden-relative prefix.
    NotGardenRelative(String),
    /// The path is (or is under) a machine-specific dir (`MACHINE_DIRS`).
    MachineDir(String),
    /// The path starts with a reserved top-level name (`RESERVED_TOP_DIRS`)
    /// or contains an infrastructure name (`INFRA_NAMES`) at any depth.
    ReservedPath(String),
    /// The path overlaps an existing share's mount prefix (nested or identical).
    /// v1 shares must be disjoint; carries the conflicting member id.
    Overlapping { path: String, conflict: String },
}

impl std::fmt::Display for ShareValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGardenRelative(p) => {
                write!(f, "{p:?} is not a clean garden-relative path")
            }
            Self::MachineDir(p) => write!(
                f,
                "{p:?} is (or is under) a machine-specific dir and cannot be shared"
            ),
            Self::ReservedPath(p) => write!(
                f,
                "{p:?} names (or contains) a reserved soft-fig dir and cannot be shared"
            ),
            Self::Overlapping { path, conflict } => write!(
                f,
                "{path:?} overlaps the mount of existing share {conflict:?} (v1 shares must be disjoint)"
            ),
        }
    }
}

impl std::error::Error for ShareValidationError {}

/// Split a garden-relative path into non-empty components, or `None` if it is
/// absolute, empty, or contains a `..` traversal.
fn clean_components(path: &str) -> Option<Vec<&str>> {
    if path.starts_with('/') {
        return None;
    }
    let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if comps.is_empty() || comps.contains(&"..") {
        return None;
    }
    Some(comps)
}

/// Whether `a`'s components are a prefix of (or equal to) `b`'s — the disjoint
/// test's core. Component-wise so `projects` never "prefixes" `projects-x`.
fn is_prefix(a: &[&str], b: &[&str]) -> bool {
    a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

/// Validate a proposed shared-subtree `mount_path` against the existing
/// membership: reject machine-specific dirs and any overlap with an existing
/// share (v1 requires **disjoint** prefixes). Pure — no I/O.
pub fn validate_share_add(
    membership: &SharedSubtreesConfig,
    mount_path: &str,
) -> Result<(), ShareValidationError> {
    let comps =
        clean_components(mount_path).ok_or_else(|| ShareValidationError::NotGardenRelative(mount_path.to_string()))?;

    if MACHINE_DIRS.contains(&comps[0]) {
        return Err(ShareValidationError::MachineDir(mount_path.to_string()));
    }
    if RESERVED_TOP_DIRS.contains(&comps[0]) || comps.iter().any(|c| INFRA_NAMES.contains(c)) {
        return Err(ShareValidationError::ReservedPath(mount_path.to_string()));
    }

    for existing in &membership.subtrees {
        // An existing entry with a garbage path can't have been added through
        // this validator; skip rather than panic (be liberal on read).
        let Some(ex) = clean_components(&existing.mount_path) else {
            continue;
        };
        if is_prefix(&comps, &ex) || is_prefix(&ex, &comps) {
            return Err(ShareValidationError::Overlapping {
                path: mount_path.to_string(),
                conflict: existing.id.clone(),
            });
        }
    }
    Ok(())
}

impl ChainRegistry {
    /// Build the live registry from committed membership + the per-device local
    /// toggle sidecar. Each member becomes a shared [`Chain`] whose `enabled`
    /// flag is `!local.is_disabled(id)`. An **empty** membership yields exactly
    /// [`ChainRegistry::device_only`] — the additive, off-by-default guarantee.
    pub fn from_shared_config(membership: &SharedSubtreesConfig, local: &LocalToggles) -> Self {
        let shared = membership
            .subtrees
            .iter()
            .map(|e| {
                let enabled = !local.is_disabled(&e.id);
                let mut chain =
                    Chain::shared(e.id.clone(), e.ref_name.clone(), PathBuf::from(&e.mount_path), enabled);
                chain.key_id = e.key_id.clone();
                chain
            })
            .collect();
        Self::new(Chain::device(), shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainKind;
    use crate::repo::TIP_REF;
    use std::path::Path;

    const SAMPLE: &str = r#"
[[subtree]]
id = "journals"
mount_path = "projects/journals"
ref_name = "chain/journals"

[[subtree]]
id = "wiki"
mount_path = "notes/wiki"
ref_name = "chain/wiki"
key_id = "S-placeholder"
recommended_path = "shared/wiki"
"#;

    #[test]
    fn parses_sample_config_into_a_correct_registry() {
        let cfg = SharedSubtreesConfig::from_toml_str(SAMPLE).unwrap();
        assert_eq!(cfg.subtrees.len(), 2);
        assert_eq!(cfg.subtrees[1].key_id.as_deref(), Some("S-placeholder"));
        // The pre-placement row parses with no recommendation; the wiki row's
        // recommendation is advisory — the registry mounts at THIS device's
        // `mount_path` (`notes/wiki`), never at the sharer's recommendation.
        assert_eq!(cfg.subtrees[0].recommended_path, None);
        assert_eq!(cfg.subtrees[1].recommended_path.as_deref(), Some("shared/wiki"));

        let reg = ChainRegistry::from_shared_config(&cfg, &LocalToggles::default());
        // device + 2 enabled shared chains all live.
        assert_eq!(reg.enabled_chains().count(), 3);
        assert_eq!(reg.owning_chain(Path::new("projects/journals/2026.md")).id, "journals");
        assert_eq!(reg.owning_chain(Path::new("notes/wiki/index.md")).id, "wiki");
        // The recommendation is NOT a mount: content there stays device-owned.
        assert!(reg.is_device_owned(Path::new("shared/wiki/index.md")));
        // Elsewhere → device.
        assert!(reg.is_device_owned(Path::new("shell/aliases.md")));
        // A sibling that only shares a string prefix stays device-owned.
        assert!(reg.is_device_owned(Path::new("projects/journals-scratch/x")));
    }

    #[test]
    fn empty_membership_is_byte_identical_to_device_only() {
        let reg = ChainRegistry::from_shared_config(&SharedSubtreesConfig::default(), &LocalToggles::default());
        for p in ["a.md", "projects/app/x", "hardware/cpu", ""] {
            let c = reg.owning_chain(Path::new(p));
            assert_eq!(c.kind, ChainKind::Device);
            assert_eq!(c.ref_name, TIP_REF);
        }
        assert_eq!(reg.enabled_chains().count(), 1);
    }

    #[test]
    fn local_disable_flips_membership_without_touching_the_config() {
        let cfg = SharedSubtreesConfig::from_toml_str(SAMPLE).unwrap();
        let mut local = LocalToggles::default();
        assert!(local.disable("journals"));
        assert!(!local.disable("journals")); // idempotent

        let reg = ChainRegistry::from_shared_config(&cfg, &local);
        // Disabled → transparent: the device chain owns its subtree again.
        assert!(reg.is_device_owned(Path::new("projects/journals/2026.md")));
        // The still-enabled member is unaffected.
        assert_eq!(reg.owning_chain(Path::new("notes/wiki/x")).id, "wiki");
        assert_eq!(reg.enabled_chains().count(), 2); // device + wiki

        // Re-enable recomposes the full view.
        assert!(local.enable("journals"));
        let reg = ChainRegistry::from_shared_config(&cfg, &local);
        assert_eq!(reg.owning_chain(Path::new("projects/journals/x")).id, "journals");
        assert_eq!(reg.enabled_chains().count(), 3);

        // Crucially, the committed membership is untouched by the toggle: same
        // ids, key-ids, refs (the ceremony-free guarantee, at the data level).
        let reparsed = SharedSubtreesConfig::from_toml_str(SAMPLE).unwrap();
        assert_eq!(cfg, reparsed);
    }

    #[test]
    fn validate_rejects_machine_dirs() {
        let empty = SharedSubtreesConfig::default();
        for p in ["hardware", "services/waydroid", "os/boot", "storage/luks", "snapshots/packages"] {
            assert!(
                matches!(validate_share_add(&empty, p), Err(ShareValidationError::MachineDir(_))),
                "{p} should be rejected as a machine dir"
            );
        }
        // A non-denylisted dir is fine.
        assert!(validate_share_add(&empty, "projects/journals").is_ok());
    }

    #[test]
    fn validate_rejects_overlapping_prefixes() {
        let cfg = SharedSubtreesConfig {
            subtrees: vec![SharedSubtreeEntry {
                id: "proj".into(),
                mount_path: "projects".into(),
                ref_name: "chain/proj".into(),
                key_id: None,
                recommended_path: None,
            }],
        };
        // Nested under an existing share → overlap.
        assert!(matches!(
            validate_share_add(&cfg, "projects/app"),
            Err(ShareValidationError::Overlapping { conflict, .. }) if conflict == "proj"
        ));
        // Existing share nested under the new one → overlap (both directions).
        let cfg2 = SharedSubtreesConfig {
            subtrees: vec![SharedSubtreeEntry {
                id: "app".into(),
                mount_path: "projects/app".into(),
                ref_name: "chain/app".into(),
                key_id: None,
                recommended_path: None,
            }],
        };
        assert!(matches!(
            validate_share_add(&cfg2, "projects"),
            Err(ShareValidationError::Overlapping { .. })
        ));
        // Identical mount → overlap.
        assert!(matches!(
            validate_share_add(&cfg, "projects"),
            Err(ShareValidationError::Overlapping { .. })
        ));
        // A disjoint sibling is accepted.
        assert!(validate_share_add(&cfg, "notes/wiki").is_ok());
        // A mere string-prefix sibling is disjoint (component-wise), so accepted.
        assert!(validate_share_add(&cfg, "projects-scratch").is_ok());
    }

    #[test]
    fn validate_rejects_reserved_and_infra_names() {
        let empty = SharedSubtreesConfig::default();
        // Top-level reserved dirs — first component only.
        for p in ["config", "config/deploy", "growlight", "growlight/backlog", "journal", "inbox"] {
            assert!(
                matches!(validate_share_add(&empty, p), Err(ShareValidationError::ReservedPath(_))),
                "{p} should be rejected as reserved"
            );
        }
        // Infrastructure names — rejected at any depth.
        for p in [".softfig", ".claude", ".softfigignore", "projects/app/.claude", "notes/.softfig/x"] {
            assert!(
                matches!(validate_share_add(&empty, p), Err(ShareValidationError::ReservedPath(_))),
                "{p} should be rejected as infrastructure"
            );
        }
        // A nested dir merely *named* like a reserved top-level is content.
        assert!(validate_share_add(&empty, "projects/app/config").is_ok());
    }

    #[test]
    fn lenient_parse_tolerates_unknown_fields_strict_rejects_them() {
        // A "newer schema" file: additive top-level + row fields.
        let newer = r#"
schema_rev = 2

[[subtree]]
id = "journals"
mount_path = "projects/journals"
ref_name = "chain/journals"
recommended_path = "projects/journals"
write_turn = "device-b"
"#;
        // Strict (the mutation path) refuses — a rewrite would drop the
        // fields this version doesn't understand.
        assert!(SharedSubtreesConfig::from_toml_str(newer).is_err());
        // Lenient (the compose path) still routes what it understands,
        // including the fields it does know (the recommendation survives).
        let cfg = SharedSubtreesConfig::from_toml_str_lenient(newer).unwrap();
        assert_eq!(cfg.subtrees.len(), 1);
        assert_eq!(cfg.subtrees[0].id, "journals");
        assert_eq!(cfg.subtrees[0].recommended_path.as_deref(), Some("projects/journals"));
        // A row missing a required field is corrupt for both.
        let corrupt = "[[subtree]]\nid = \"x\"\n";
        assert!(SharedSubtreesConfig::from_toml_str_lenient(corrupt).is_err());
        assert!(SharedSubtreesConfig::from_toml_str(corrupt).is_err());
    }

    #[test]
    fn validate_rejects_non_garden_relative_paths() {
        let empty = SharedSubtreesConfig::default();
        for p in ["", "/abs/path", "..", "projects/../hardware", "/"] {
            assert!(
                matches!(validate_share_add(&empty, p), Err(ShareValidationError::NotGardenRelative(_))),
                "{p:?} should be rejected as not garden-relative"
            );
        }
    }

    #[test]
    fn toml_round_trips() {
        let cfg = SharedSubtreesConfig::from_toml_str(SAMPLE).unwrap();
        let back = SharedSubtreesConfig::from_toml_str(&cfg.to_toml().unwrap()).unwrap();
        assert_eq!(cfg, back);

        let mut local = LocalToggles::default();
        local.disable("journals");
        let back = LocalToggles::from_toml_str(&local.to_toml().unwrap()).unwrap();
        assert_eq!(local, back);
    }
}
