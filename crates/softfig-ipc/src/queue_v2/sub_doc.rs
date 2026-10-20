//! §6.7's rule for the text a member supplies to `growlight_add_sub_milestone`
//! (`queue-v2-scheduling` slice 010): keeperd writes the sub-milestone's docs
//! from the structured fields, so none of that text may carry the metadata
//! lines the resolvers and the grants enforcement read — `> Model:`,
//! `> Grants:`, `> Worktree:`. Otherwise a member could hand its own sub a
//! model, a folder grant or a worktree the parent never allowed.
//!
//! One rule, two callers: growlightd's §6.3 validation (the `field_not_allowed`
//! refusal the agent sees, before anything commits) and keeperd's
//! `queue_v2_add_sub` (the writer's backstop). Pure.
//!
//! **Where each key is refused.** The mission, the finish criteria and every
//! slice title may carry none of the three. A slice **body** may carry
//! `> Model:` — §6.7's one exception, held to the subset rule instead
//! (`model_choice::validate_declared_subset`) — but not `> Grants:` or
//! `> Worktree:`.

/// The blockquote metadata keys a member may not write into a sub-milestone
/// (§6.7), lowercase.
pub const SUB_DOC_RESERVED: [&str; 3] =
    [crate::item_meta::MODEL, crate::item_meta::GRANTS, crate::item_meta::WORKTREE];

/// The reserved keys a member-supplied slice body may not carry: everything
/// but `model`, which §6.7 lets a slice body declare (subset-checked).
pub const SLICE_BODY_RESERVED: [&str; 2] = [crate::item_meta::GRANTS, crate::item_meta::WORKTREE];

/// The guard-side reads of the shared metadata scanner, re-exported where the
/// §6.7 rule has always named them: [`reserved_field`] finds the first
/// `> <key>:` line for any of `keys` (fenced or not, value ignored, so an empty
/// `> Model:` is refused too), and [`reserved_lines`] lists every such line —
/// keeperd's member-write guard compares those before and after a write.
pub use crate::item_meta::{reserved_field, reserved_lines};

/// One slice of a member's sub-milestone, as the rule reads it.
#[derive(Debug, Clone, Copy)]
pub struct SubSliceText<'a> {
    pub title: &'a str,
    pub body: &'a str,
}

/// A reserved line in a member's sub-milestone text: which field held it and
/// which key it declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldViolation {
    /// `mission`, `finish_criteria`, `slices[<i>].title` or `slices[<i>].body`.
    pub field: String,
    /// The reserved key, lowercase (`model`, `grants`, `worktree`).
    pub key: &'static str,
}

impl FieldViolation {
    /// The refusal text: what was refused and why.
    pub fn message(&self) -> String {
        let key = crate::item_meta::display_key(self.key);
        format!(
            "`{}` carries a `> {key}:` line — keeperd writes a sub-milestone's docs from \
             its fields, and a member may not set {} there{}",
            self.field,
            match self.key {
                "model" => "its model",
                "grants" => "its folder grants",
                _ => "its worktree",
            },
            if self.key == "model" && !self.field.ends_with(".body") {
                " (a slice body may declare `> Model:`, a subset of what it inherits)"
            } else {
                ""
            }
        )
    }
}

/// §6.7 over a whole `growlight_add_sub_milestone` call: the first reserved
/// line, checked in field order (mission, criteria, then each slice's title
/// and body), or `None` when the text is clean.
pub fn sub_doc_violation(
    mission: &str,
    finish_criteria: &str,
    slices: &[SubSliceText<'_>],
) -> Option<FieldViolation> {
    let hit = |field: String, text: &str, keys: &[&'static str]| {
        reserved_field(text, keys).map(|key| FieldViolation { field, key })
    };
    hit("mission".into(), mission, &SUB_DOC_RESERVED)
        .or_else(|| hit("finish_criteria".into(), finish_criteria, &SUB_DOC_RESERVED))
        .or_else(|| {
            slices.iter().enumerate().find_map(|(i, s)| {
                hit(format!("slices[{i}].title"), s.title, &SUB_DOC_RESERVED)
                    .or_else(|| hit(format!("slices[{i}].body"), s.body, &SLICE_BODY_RESERVED))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice<'a>(title: &'a str, body: &'a str) -> SubSliceText<'a> {
        SubSliceText {
            title,
            body,
        }
    }

    #[test]
    fn a_reserved_line_is_found_the_way_the_resolver_reads_one() {
        assert_eq!(reserved_field("> Model: flash", &SUB_DOC_RESERVED), Some("model"));
        assert_eq!(reserved_field("  >   grants : ~/x", &SUB_DOC_RESERVED), Some("grants"));
        assert_eq!(reserved_field("> WORKTREE:", &SUB_DOC_RESERVED), Some("worktree"), "an empty value counts");
        assert_eq!(reserved_field("Model: flash (prose)", &SUB_DOC_RESERVED), None, "prose is not metadata");
        assert_eq!(reserved_field("> Last reviewed: 2026-10-14", &SUB_DOC_RESERVED), None);
        assert_eq!(reserved_field("> Model: flash", &SLICE_BODY_RESERVED), None);
    }

    #[test]
    fn reserved_lines_are_every_matching_metadata_line_in_order() {
        let doc = "# t\n\n> Model: flash\nprose Model: x\n  >  model : claude \n> Grants: ~/x\n";
        assert_eq!(reserved_lines(doc, &["model"]), vec!["> Model: flash", ">  model : claude"]);
        assert_eq!(reserved_lines(doc, &["grants"]), vec!["> Grants: ~/x"]);
        assert!(reserved_lines("# no metadata\n", &SUB_DOC_RESERVED).is_empty());
    }

    #[test]
    fn mission_criteria_and_titles_refuse_all_three_and_bodies_refuse_grants_and_worktree() {
        let clean = [slice("Build it", "> Model: flash\n\nwork")];
        assert_eq!(sub_doc_violation("do x", "x works", &clean), None, "a body may declare a model");

        let v = sub_doc_violation("do x\n> Model: claude", "ok", &clean).unwrap();
        assert_eq!((v.field.as_str(), v.key), ("mission", "model"));
        let v = sub_doc_violation("do x", "> Worktree: /tmp", &clean).unwrap();
        assert_eq!((v.field.as_str(), v.key), ("finish_criteria", "worktree"));
        let v = sub_doc_violation("do x", "ok", &[slice("> Model: claude", "b")]).unwrap();
        assert_eq!((v.field.as_str(), v.key), ("slices[0].title", "model"));
        let v = sub_doc_violation("do x", "ok", &[clean[0], slice("t", "> Grants: ~/projects")]).unwrap();
        assert_eq!((v.field.as_str(), v.key), ("slices[1].body", "grants"));
        assert!(v.message().contains("`slices[1].body` carries a `> Grants:` line"), "{}", v.message());
    }
}
