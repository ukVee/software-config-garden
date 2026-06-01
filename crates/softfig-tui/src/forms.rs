//! Action forms: the in-TUI surface for the six M3a write verbs.
//!
//! Each form validates client-side (mirroring the daemon's
//! `actions::conventions` rules) for instant feedback, then produces the
//! `(op, args)` pair the IPC worker sends. The daemon stays the
//! authority — a value that slips through still gets a typed `ErrorKind`
//! back. Pure logic; unit-tested without a terminal.

use serde_json::{json, Value};
use softfig_ipc::op;

use crate::textarea::TextArea;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    LogDecision,
    LogIncident,
    Archive,
    AddProject,
    RefreshSnapshot,
    ProposeDocUpdate,
}

impl ActionKind {
    pub const ALL: [ActionKind; 6] = [
        ActionKind::LogDecision,
        ActionKind::LogIncident,
        ActionKind::Archive,
        ActionKind::AddProject,
        ActionKind::RefreshSnapshot,
        ActionKind::ProposeDocUpdate,
    ];

    /// The palette command keyword for this action.
    pub fn command_name(self) -> &'static str {
        match self {
            ActionKind::LogDecision => "log_decision",
            ActionKind::LogIncident => "log_incident",
            ActionKind::Archive => "archive",
            ActionKind::AddProject => "add_project",
            ActionKind::RefreshSnapshot => "refresh_snapshot",
            ActionKind::ProposeDocUpdate => "propose",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            ActionKind::LogDecision => "log_decision",
            ActionKind::LogIncident => "log_incident",
            ActionKind::Archive => "archive",
            ActionKind::AddProject => "add_project",
            ActionKind::RefreshSnapshot => "refresh_snapshot",
            ActionKind::ProposeDocUpdate => "propose_doc_update",
        }
    }
}

#[derive(Debug)]
pub enum FieldValue {
    Line(String),
    Body(TextArea),
}

#[derive(Debug)]
pub struct Field {
    pub label: &'static str,
    pub optional: bool,
    pub value: FieldValue,
}

impl Field {
    fn line(label: &'static str, optional: bool) -> Self {
        Field {
            label,
            optional,
            value: FieldValue::Line(String::new()),
        }
    }

    fn body(label: &'static str) -> Self {
        Field {
            label,
            optional: false,
            value: FieldValue::Body(TextArea::new()),
        }
    }

    pub fn is_body(&self) -> bool {
        matches!(self.value, FieldValue::Body(_))
    }

    fn as_str(&self) -> String {
        match &self.value {
            FieldValue::Line(s) => s.clone(),
            FieldValue::Body(t) => t.text(),
        }
    }
}

#[derive(Debug)]
pub struct ActionForm {
    pub kind: ActionKind,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
}

impl ActionForm {
    pub fn for_kind(kind: ActionKind) -> Self {
        let fields = match kind {
            ActionKind::LogDecision => vec![
                Field::line("slug", false),
                Field::line("summary (optional)", true),
                Field::body("body"),
            ],
            ActionKind::LogIncident => vec![
                Field::line("slug", false),
                Field::line("summary", false),
                Field::line("date YYYYMMDD (optional)", true),
                Field::body("body"),
            ],
            ActionKind::Archive => vec![
                Field::line("src", false),
                Field::line("archive_name (optional)", true),
            ],
            ActionKind::AddProject => vec![
                Field::line("name", false),
                Field::line("repo_path (optional)", true),
                Field::line("summary (optional)", true),
            ],
            ActionKind::RefreshSnapshot => vec![
                Field::line("path (under snapshots/)", false),
                Field::body("content"),
            ],
            ActionKind::ProposeDocUpdate => vec![
                Field::line("path", false),
                Field::line("summary", false),
                Field::line("project", false),
                Field::body("content"),
            ],
        };
        ActionForm {
            kind,
            fields,
            focus: 0,
            error: None,
        }
    }

    pub fn focus_next(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    pub fn focus_prev(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
        }
    }

    fn focused(&mut self) -> &mut Field {
        &mut self.fields[self.focus]
    }

    pub fn input_char(&mut self, c: char) {
        match &mut self.focused().value {
            FieldValue::Line(s) => s.push(c),
            FieldValue::Body(t) => t.insert_char(c),
        }
    }

    pub fn backspace(&mut self) {
        match &mut self.focused().value {
            FieldValue::Line(s) => {
                s.pop();
            }
            FieldValue::Body(t) => t.backspace(),
        }
    }

    /// Enter: newline inside a body field; advance focus otherwise.
    pub fn enter(&mut self) {
        match &mut self.focused().value {
            FieldValue::Body(t) => t.newline(),
            FieldValue::Line(_) => self.focus_next(),
        }
    }

    fn val(&self, idx: usize) -> String {
        self.fields[idx].as_str()
    }

    /// Validate + build the `(op, args)` to send. `Err` carries a
    /// human-readable reason shown inline; the form stays open.
    pub fn to_request(&self) -> Result<(&'static str, Value), String> {
        match self.kind {
            ActionKind::LogDecision => {
                let slug = self.val(0);
                validate_slug(&slug)?;
                let body = self.val(2);
                if body.trim().is_empty() {
                    return Err("body must not be empty".into());
                }
                let mut args = json!({ "slug": slug, "body": body });
                let summary = self.val(1);
                if !summary.trim().is_empty() {
                    args["summary"] = json!(summary);
                }
                Ok((op::LOG_DECISION, args))
            }
            ActionKind::LogIncident => {
                let slug = self.val(0);
                validate_slug(&slug)?;
                let summary = self.val(1);
                if summary.trim().is_empty() {
                    return Err("summary must not be empty".into());
                }
                let body = self.val(3);
                if body.trim().is_empty() {
                    return Err("body must not be empty".into());
                }
                let mut args = json!({ "slug": slug, "summary": summary, "body": body });
                let date = self.val(2);
                if !date.trim().is_empty() {
                    validate_date(date.trim())?;
                    args["date"] = json!(date.trim());
                }
                Ok((op::LOG_INCIDENT, args))
            }
            ActionKind::Archive => {
                let src = self.val(0);
                if src.trim().is_empty() {
                    return Err("src must not be empty".into());
                }
                let mut args = json!({ "src": src.trim() });
                let name = self.val(1);
                if !name.trim().is_empty() {
                    args["archive_name"] = json!(name.trim());
                }
                Ok((op::ARCHIVE, args))
            }
            ActionKind::AddProject => {
                let name = self.val(0);
                validate_project_name(&name)?;
                let mut args = json!({ "name": name });
                let repo = self.val(1);
                if !repo.trim().is_empty() {
                    args["repo_path"] = json!(repo.trim());
                }
                let summary = self.val(2);
                if !summary.trim().is_empty() {
                    args["summary"] = json!(summary.trim());
                }
                Ok((op::ADD_PROJECT, args))
            }
            ActionKind::RefreshSnapshot => {
                let path = self.val(0);
                let path = path.trim();
                if path.is_empty() {
                    return Err("path must not be empty".into());
                }
                if !path.starts_with("snapshots/") {
                    return Err("path must be under snapshots/".into());
                }
                let content = self.val(1);
                Ok((op::REFRESH_SNAPSHOT, json!({ "path": path, "content": content })))
            }
            ActionKind::ProposeDocUpdate => {
                let path = self.val(0);
                let path = path.trim();
                if path.is_empty() {
                    return Err("path must not be empty".into());
                }
                let summary = self.val(1);
                if summary.trim().is_empty() {
                    return Err("summary must not be empty".into());
                }
                let project = self.val(2);
                if project.trim().is_empty() {
                    return Err("project must not be empty".into());
                }
                let content = self.val(3);
                Ok((
                    op::PROPOSE_DOC_UPDATE,
                    json!({
                        "summary": summary.trim(),
                        "project": project.trim(),
                        "files": [{ "path": path, "content": content }],
                    }),
                ))
            }
        }
    }
}

pub fn validate_slug(slug: &str) -> Result<(), String> {
    if slug.is_empty() || slug.len() > 64 {
        return Err("slug length must be 1–64".into());
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("slug charset must be [a-z0-9-]".into());
    }
    Ok(())
}

pub fn validate_project_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("project name length must be 1–64".into());
    }
    let ok_chars = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let first_last_alnum = {
        let bytes = name.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        (first.is_ascii_lowercase() || first.is_ascii_digit())
            && (last.is_ascii_lowercase() || last.is_ascii_digit())
    };
    if !ok_chars || !first_last_alnum {
        return Err("project name must match [a-z0-9]([a-z0-9-]*[a-z0-9])?".into());
    }
    Ok(())
}

pub fn validate_date(date: &str) -> Result<(), String> {
    if date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err("date must be 8 digits (YYYYMMDD)".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules() {
        assert!(validate_slug("softfig-m3b-impl").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("Has_Caps").is_err());
        assert!(validate_slug(&"x".repeat(65)).is_err());
    }

    #[test]
    fn project_name_rules() {
        assert!(validate_project_name("sliver-dock").is_ok());
        assert!(validate_project_name("a").is_ok());
        assert!(validate_project_name("-leading").is_err());
        assert!(validate_project_name("trailing-").is_err());
        assert!(validate_project_name("Caps").is_err());
    }

    #[test]
    fn date_rules() {
        assert!(validate_date("20260531").is_ok());
        assert!(validate_date("2026-05-31").is_err());
        assert!(validate_date("123").is_err());
    }

    #[test]
    fn log_decision_builds_request() {
        let mut f = ActionForm::for_kind(ActionKind::LogDecision);
        // slug field focused first
        for c in "my-decision".chars() {
            f.input_char(c);
        }
        f.focus = 2; // body
        for c in "rationale".chars() {
            f.input_char(c);
        }
        let (op, args) = f.to_request().unwrap();
        assert_eq!(op, op::LOG_DECISION);
        assert_eq!(args["slug"], "my-decision");
        assert_eq!(args["body"], "rationale");
        assert!(args.get("summary").is_none());
    }

    #[test]
    fn refresh_snapshot_requires_snapshots_prefix() {
        let mut f = ActionForm::for_kind(ActionKind::RefreshSnapshot);
        for c in "packages/pacman/list.md".chars() {
            f.input_char(c);
        }
        assert!(f.to_request().is_err());

        let mut f = ActionForm::for_kind(ActionKind::RefreshSnapshot);
        for c in "snapshots/packages/pacman/list.md".chars() {
            f.input_char(c);
        }
        f.focus = 1;
        for c in "data".chars() {
            f.input_char(c);
        }
        let (op, args) = f.to_request().unwrap();
        assert_eq!(op, op::REFRESH_SNAPSHOT);
        assert_eq!(args["path"], "snapshots/packages/pacman/list.md");
        assert_eq!(args["content"], "data");
    }

    #[test]
    fn enter_in_line_advances_focus_in_body_newlines() {
        let mut f = ActionForm::for_kind(ActionKind::LogDecision);
        assert_eq!(f.focus, 0);
        f.enter(); // line field → advance
        assert_eq!(f.focus, 1);
        f.focus = 2; // body
        f.input_char('a');
        f.enter(); // body → newline
        f.input_char('b');
        assert_eq!(f.val(2), "a\nb");
    }
}
