//! Auto-classification of watcher dirty sets into commit intents.
//!
//! Conservative posture per `meta/spec-keeper.md`: only fire a typed
//! intent when the dirty set is homogeneous and matches a rule. Mixed
//! sets fall back to `manual_edit`. `schema_change`, `rollback`, and
//! `snapshot_refresh` are never auto-classified — those need explicit
//! caller intent.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct Classified {
    pub intent: String,
    pub payload: serde_json::Value,
}

/// Inputs the watcher hands to the classifier: the set of repo-relative
/// paths that changed, with a hint for created vs renamed.
#[derive(Debug, Clone)]
pub struct DirtySet {
    pub created: Vec<String>,
    pub modified: Vec<String>,
    pub removed: Vec<String>,
    pub renamed_to_archive: Vec<(String, String)>,
}

impl DirtySet {
    pub fn is_empty(&self) -> bool {
        self.created.is_empty()
            && self.modified.is_empty()
            && self.removed.is_empty()
            && self.renamed_to_archive.is_empty()
    }

    pub fn all_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.created.iter().cloned());
        out.extend(self.modified.iter().cloned());
        out.extend(self.removed.iter().cloned());
        for (_, to) in &self.renamed_to_archive {
            out.push(to.clone());
        }
        out.sort();
        out.dedup();
        out
    }
}

pub fn classify(dirty: &DirtySet) -> Classified {
    // Decision file path → decision_logged.
    if dirty.modified.is_empty()
        && dirty.removed.is_empty()
        && dirty.renamed_to_archive.is_empty()
        && dirty.created.len() == 1
    {
        let p = &dirty.created[0];
        if let Some(slug) = decision_slug_from(p) {
            return Classified {
                intent: "decision_logged".into(),
                payload: serde_json::json!({ "slug": slug }),
            };
        }
        if let Some(slug) = incident_slug_from(p) {
            return Classified {
                intent: "incident_logged".into(),
                payload: serde_json::json!({ "slug": slug }),
            };
        }
    }

    // archive_move: every change is a rename into journal/archive/**.
    if dirty.created.is_empty()
        && dirty.modified.is_empty()
        && dirty.removed.is_empty()
        && !dirty.renamed_to_archive.is_empty()
    {
        let moves: Vec<serde_json::Value> = dirty
            .renamed_to_archive
            .iter()
            .map(|(from, to)| {
                serde_json::json!({"from": from, "to": to})
            })
            .collect();
        return Classified {
            intent: "archive_move".into(),
            payload: serde_json::json!({ "moves": moves }),
        };
    }

    // Fallback: manual_edit with the full dirty path list.
    Classified {
        intent: "manual_edit".into(),
        payload: serde_json::json!({
            "files": dirty.all_paths(),
            "summary": serde_json::Value::Null,
        }),
    }
}

fn decision_slug_from(rel: &str) -> Option<String> {
    let p = Path::new(rel);
    let parent = p.parent()?;
    if parent != Path::new("journal/decisions") {
        return None;
    }
    let stem = p.file_name()?.to_str()?;
    let stem = stem.strip_suffix(".md")?;
    let slug = stem.strip_prefix("decision-")?;
    if slug.is_empty() {
        return None;
    }
    Some(slug.to_string())
}

fn incident_slug_from(rel: &str) -> Option<String> {
    let p = Path::new(rel);
    let parent = p.parent()?;
    if parent != Path::new("journal/incidents") {
        return None;
    }
    let stem = p.file_name()?.to_str()?;
    let stem = stem.strip_suffix(".md")?;
    if !stem.starts_with("incident-") {
        return None;
    }
    Some(stem.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirty_created(paths: &[&str]) -> DirtySet {
        DirtySet {
            created: paths.iter().map(|s| s.to_string()).collect(),
            modified: vec![],
            removed: vec![],
            renamed_to_archive: vec![],
        }
    }

    #[test]
    fn classifies_decision() {
        let c = classify(&dirty_created(&["journal/decisions/decision-foo.md"]));
        assert_eq!(c.intent, "decision_logged");
        assert_eq!(c.payload["slug"], "foo");
    }

    #[test]
    fn classifies_incident() {
        let c = classify(&dirty_created(&[
            "journal/incidents/incident-20260509-bar.md",
        ]));
        assert_eq!(c.intent, "incident_logged");
        assert_eq!(c.payload["slug"], "incident-20260509-bar");
    }

    #[test]
    fn falls_back_to_manual_edit() {
        let mut d = dirty_created(&["a.md"]);
        d.modified.push("b.md".into());
        let c = classify(&d);
        assert_eq!(c.intent, "manual_edit");
    }

    #[test]
    fn classifies_archive_move() {
        let d = DirtySet {
            created: vec![],
            modified: vec![],
            removed: vec![],
            renamed_to_archive: vec![(
                "projects/old/CLAUDE.md".into(),
                "journal/archive/old/CLAUDE.md".into(),
            )],
        };
        let c = classify(&d);
        assert_eq!(c.intent, "archive_move");
    }
}
