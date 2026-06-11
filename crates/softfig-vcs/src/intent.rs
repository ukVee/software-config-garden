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
    "archive_move",
    "project_added",
    "project_archived",
    "schema_change",
    "rollback",
    "vault_seal",
    "vault_reveal",
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
     incident_logged, note_added, note_revised, archive_move, project_added, \
     project_archived, schema_change, rollback, vault_seal, vault_reveal";

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
