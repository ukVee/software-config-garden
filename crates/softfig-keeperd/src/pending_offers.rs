//! Device-local pending share-offers (M5f slice 003).
//!
//! A share-offer a ring peer fanned to us is held here — **never** in the
//! committed garden / shared chain — until this device *accepts* it at a mount
//! path of its own choosing. Same never-committed `.softfig/` sidecar posture as
//! the peers endpoint cache (`softfig-net`) and the shared-subtree local toggles
//! (`.softfig/shared-subtrees-local.toml`): an offer is device-local state,
//! meaningless to any other member ([[decision-shared-subtree-recipient-
//! placement]]), so it stays out of the ring-signed membership file.
//!
//! The file is `[[offer]]` array-of-tables, mirroring `shared-subtrees.toml`.
//! Written tmp+rename (the single-writer daemon mutex makes the fixed tmp name
//! safe); a broken/absent file parses as empty, which is self-healing because
//! the sharer re-fans every reconcile tick.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Filename of the pending-offers sidecar within `.softfig/`.
pub const PENDING_OFFERS_FILE: &str = "pending-share-offers.toml";

/// One pending share-offer, as received over the wire and held device-locally
/// until accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOffer {
    /// The share's stable id — what the accept verb names.
    pub id: String,
    /// The chain ref (`chain/<id>`) an accepted mount will track.
    pub ref_name: String,
    /// The sharer's advisory placement (the accept default). `None` = no hint,
    /// so the recipient must name a mount path. Advisory only — never
    /// authoritative, never this device's actual placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_path: Option<String>,
    /// The offering peer's device fingerprint (lowercase hex) — provenance for
    /// the surface (slice 006); not an authorization input.
    pub offered_by: String,
}

/// The device-local pending-offer store (`.softfig/pending-share-offers.toml`).
/// Keyed by share id ([`PendingOffers::upsert`] dedups), so a re-offer is an
/// idempotent refresh rather than a duplicate row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingOffers {
    #[serde(default, rename = "offer")]
    offers: Vec<PendingOffer>,
}

impl PendingOffers {
    /// Path to the sidecar for a given state dir:
    /// `<state_dir>/.softfig/pending-share-offers.toml`.
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(".softfig").join(PENDING_OFFERS_FILE)
    }

    /// Load the sidecar. A missing file is an empty store (the common case — an
    /// offer is re-fanned every reconcile tick, so a lost sidecar self-heals); a
    /// broken parse logs and also yields empty (fail-open, like the local
    /// toggles) — a stale pending offer is recreated on the sharer's next fan.
    pub fn load(state_dir: &Path) -> Self {
        let path = Self::path(state_dir);
        match std::fs::read_to_string(&path) {
            Ok(raw) => toml::from_str(&raw).unwrap_or_else(|e| {
                eprintln!(
                    "keeperd: {} parse failed ({e}); no pending offers",
                    path.display()
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    /// Atomically persist (tmp+rename), creating `.softfig/` if needed. Never
    /// committed, so the two filesystem events are harmless (outside the VCS
    /// walk).
    pub fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        let dir = state_dir.join(".softfig");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(PENDING_OFFERS_FILE);
        let tmp = dir.join(format!("{PENDING_OFFERS_FILE}.tmp"));
        let raw = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &path)
    }

    /// The pending offer for `id`, if any.
    pub fn get(&self, id: &str) -> Option<&PendingOffer> {
        self.offers.iter().find(|o| o.id == id)
    }

    /// Insert or replace an offer (idempotent upsert keyed by id — a re-offer
    /// just refreshes the row).
    pub fn upsert(&mut self, offer: PendingOffer) {
        self.offers.retain(|o| o.id != offer.id);
        self.offers.push(offer);
    }

    /// Remove the offer for `id`, returning whether one was present.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.offers.len();
        self.offers.retain(|o| o.id != id);
        before != self.offers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.offers.is_empty()
    }

    /// Iterate the pending offers (surface read; slice 006).
    pub fn iter(&self) -> impl Iterator<Item = &PendingOffer> {
        self.offers.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(id: &str, rec: Option<&str>) -> PendingOffer {
        PendingOffer {
            id: id.into(),
            ref_name: format!("chain/{id}"),
            recommended_path: rec.map(str::to_string),
            offered_by: "aa".repeat(32),
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(PendingOffers::load(dir.path()).is_empty());
    }

    #[test]
    fn save_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PendingOffers::default();
        store.upsert(offer("wiki", Some("shared/wiki")));
        store.upsert(offer("recipes", None));
        store.save(dir.path()).unwrap();

        let loaded = PendingOffers::load(dir.path());
        assert_eq!(
            loaded.get("wiki").unwrap().recommended_path.as_deref(),
            Some("shared/wiki")
        );
        assert_eq!(loaded.get("recipes").unwrap().ref_name, "chain/recipes");
        assert!(loaded.get("recipes").unwrap().recommended_path.is_none());
    }

    #[test]
    fn upsert_is_idempotent_by_id() {
        let mut store = PendingOffers::default();
        store.upsert(offer("wiki", Some("a")));
        store.upsert(offer("wiki", Some("b"))); // same id → replace, not duplicate
        assert_eq!(store.iter().count(), 1);
        assert_eq!(store.get("wiki").unwrap().recommended_path.as_deref(), Some("b"));
    }

    #[test]
    fn remove_reports_presence() {
        let mut store = PendingOffers::default();
        store.upsert(offer("wiki", None));
        assert!(store.remove("wiki"));
        assert!(!store.remove("wiki"));
        assert!(store.is_empty());
    }
}
