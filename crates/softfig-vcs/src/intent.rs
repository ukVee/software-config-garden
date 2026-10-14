//! Closed-enum commit intents (per `meta/spec-vcs.md`).
//!
//! v1 stores the intent as a name string + a free-form JSON payload. The
//! daemon and the typed-payload structs arrive in later milestones; for
//! now, the closed-enum constraint is enforced at construction time and
//! the payload is just whatever the caller passes.

use serde_json::Value;

use crate::error::{CoreError, Result};

/// Names of every intent variant the v1 closed enum recognizes. Adding a
/// new variant means amending `meta/spec-vcs.md` and bumping this list.
pub const KNOWN_INTENTS: &[&str] = &[
    "init",
    "memory_edit",
    "manual_edit",
    "snapshot_refresh",
    "decision_logged",
    "incident_logged",
    "note_added",
    "note_revised",
    "code_review_added",
    "code_review_revised",
    "monolith_split",
    "index_reindexed",
    "section_added",
    "section_edited",
    "section_appended",
    "reviewed_stamped",
    "text_patched",
    "section_removed",
    "file_unlinked",
    "batch_applied",
    "archive_move",
    "project_added",
    "project_archived",
    "baton_logged",
    "backlog_item_added",
    "queue_added",
    "slice_added",
    "item_status_set",
    "backlog_item_reordered",
    "growlight_initialized",
    "growlight_resources_set",
    "chat_message_posted",
    "inbox_read",
    "report_filed",
    "report_updated",
    "config_migrated",
    "peers_changed",
    "shared_subtrees_changed",
    "shared_ceremony",
    "shared_rekey",
    "shared_pull",
    "migrate_into_share",
    "migrate_into_share_carve",
    "sync_conflict",
    "schema_change",
    "rollback",
    "vault_seal",
    "vault_reveal",
    // growlight queue v2 (queue-v2-state slice 003): the one commit a v2 verb
    // folds all its file + view writes into. The six verbs (slices 004–006)
    // name themselves with this shape; register the generic name now and the
    // per-verb names as those slices land.
    "queue_v2_updated",
    // growlight queue v2 daemon ops (queue-v2-scheduling slice 005): the
    // handshake's commit path — one commit per op, named per op.
    "queue_v2_claimed",
    "queue_v2_status_set",
    "queue_v2_follow_ups_set",
    "queue_v2_session_logged",
    "queue_v2_deferred_set",
    // queue-v2-scheduling slice 010: growlight_add_sub_milestone's commit —
    // the sub-milestone's docs + slices.toml, the split, the placement.
    "queue_v2_sub_added",
];

/// A name + payload pair, validated against the closed enum.
#[derive(Debug, Clone)]
pub struct Intent {
    name: String,
    payload: Value,
}

impl Intent {
    pub fn new(name: &str, payload: Value) -> Result<Self> {
        if !KNOWN_INTENTS.contains(&name) {
            return Err(CoreError::UnknownIntent(
                name.to_string(),
                KNOWN_INTENTS_LIST,
            ));
        }
        if !payload.is_object() {
            return Err(CoreError::PayloadNotObject {
                intent: name.to_string(),
                got: type_name(&payload),
            });
        }
        Ok(Self {
            name: name.to_string(),
            payload,
        })
    }

    pub fn init(summary: impl Into<String>) -> Self {
        // Internal use; bypass closed-enum check (we know "init" is in the list).
        Self {
            name: "init".to_string(),
            payload: serde_json::json!({ "summary": summary.into() }),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// Move out the parts. Caller stores `name` in the `intent` column and
    /// `payload` in the `payload` column (canonicalized).
    pub fn into_parts(self) -> (String, Value) {
        (self.name, self.payload)
    }
}

const KNOWN_INTENTS_LIST: &str =
    "init, memory_edit, manual_edit, snapshot_refresh, decision_logged, \
     incident_logged, note_added, note_revised, code_review_added, \
     code_review_revised, monolith_split, index_reindexed, section_added, \
     section_edited, section_appended, reviewed_stamped, text_patched, section_removed, file_unlinked, batch_applied, archive_move, \
     project_added, project_archived, baton_logged, backlog_item_added, \
     queue_added, slice_added, item_status_set, backlog_item_reordered, growlight_initialized, \
     growlight_resources_set, \
     chat_message_posted, inbox_read, report_filed, report_updated, \
     config_migrated, \
     peers_changed, shared_subtrees_changed, shared_ceremony, shared_rekey, shared_pull, \
     migrate_into_share, migrate_into_share_carve, sync_conflict, schema_change, rollback, vault_seal, vault_reveal, queue_v2_updated, queue_v2_claimed, queue_v2_status_set, queue_v2_follow_ups_set, queue_v2_session_logged, queue_v2_deferred_set, queue_v2_sub_added";

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
