//! The writer-invariant validation and the refusal-code vocabulary (slice 002).
//!
//! Two callers share this module, and they use it differently:
//!
//! - **keeperd's file layer** (slice 003) validates every file on load,
//!   fail-closed: an invalid file schedules nothing and is alerted once
//!   (§3, "keeperd validates on every read").
//! - **the §6.8 verbs** (slices 004–006) return [`QueueRefusal`] codes as
//!   *pre-write* refusals, so keeperd replies with the spec's own vocabulary
//!   instead of inventing per-verb strings.
//!
//! [`QueueRefusal`] carries the §6.8 state-level refusal codes, plus two
//! validation-only variants for file corruption no verb code describes
//! (finding 9 in the milestone doc). The verbs never return the two
//! validation-only variants.
//!
//! What is deliberately **not** validated here:
//!
//! - §3.1 invariant 6 (a remote project's entries never get an opencode
//!   member) — member assignment is not file state; it is scheduling
//!   eligibility, enforced by `queue-v2-scheduling` (finding 1);
//! - `branch` / `parent` / `base` / `claimed` contents — the field comments
//!   describe their writers, but the invariant list does not include them;
//!   in particular a claimed row with status `queued` is valid: claims are
//!   not a file invariant (the `started` / `running` refusals are verb-level);
//! - archive rows' own `after` fields — they are history (§3.2 "moves its row
//!   here"); only live entries' links resolve and only live links form the
//!   cycle graph;
//! - the two-level sub-milestone nesting bound lives in [`sub_depth`], a
//!   helper for `slice_insert` (slice 006), not a whole-file check.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    Entry, EntryKind, EntryStatus, FinalStatus, Lane, QueueArchiveToml, QueueToml, SliceKind,
    SlicesToml,
};

/// A refused write, or a file that fails invariant validation. The first
/// eleven variants are the §6.8 state-level refusal codes, one per named code,
/// so keeperd verbs map them 1:1 onto replies. The last two are
/// validation-only (file corruption) and never cross a verb reply:
///
/// - [`QueueRefusal::MilestoneMismatch`] — a `slices.toml` whose `milestone`
///   field names a different folder than the one it was read from;
/// - [`QueueRefusal::InvalidItemShape`] — a slice item missing `follow_ups`,
///   or a `sub` item carrying one (§3.3 "slice only").
///
/// [`QueueRefusal::code`] is the wire name; the `Display` impl is the
/// human-readable alert form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueRefusal {
    /// The id or name is already taken. Verb: `queue_add_project` /
    /// `queue_add_entry` on an existing id. Validation: an id appears twice
    /// (in the live file, in the archive, or across the two).
    Exists {
        /// The id (or name) that already exists.
        id: String,
    },
    /// The name does not conform. Verb: a slug outside `[a-z0-9-]+`.
    /// Validation: a milestone path nested deeper than §3.3 allows
    /// (via [`sub_depth`]).
    BadName {
        /// The offending name.
        name: String,
    },
    /// No `[[project]]` row has this name. Validation: an entry names a
    /// project that is not in the projects table.
    UnknownProject {
        /// The project name that does not exist.
        project: String,
    },
    /// The named id resolves to nothing. Verb: `queue_update_entry` or
    /// `slice_*` on an unknown id. Validation: an `after` link names no live
    /// entry and no `done` archive row — unknown, or known but archived
    /// `dropped`, which satisfies no links (§3.2).
    UnknownId {
        /// The id that does not resolve.
        id: String,
    },
    /// The `after` links close a cycle (§3.1: "the links have no cycle").
    LinkCycle {
        /// An entry id lying on the cycle.
        id: String,
    },
    /// Verb-only: a `queue_drop` while a live entry's `after` names the id.
    LinkedFrom {
        /// The id that live links still name.
        id: String,
    },
    /// The entry is out of lane. Verb: a move that leaves the entry's lane
    /// (§6.8). Validation: a normal entry precedes an urgent one, or a
    /// restack row is not urgent (§3.1).
    LaneMismatch {
        /// The entry that violates lane placement.
        id: String,
    },
    /// The entry (or its repo) is already started. Verb: moving a started
    /// entry, or moving an `active`/`done`/`split` slice item (§6.8).
    /// Validation: a second normal-lane entry in the same repo is `active`
    /// or `paused` (§3.1: at most one).
    Started {
        /// The entry that is already started.
        id: String,
    },
    /// Verb-only: `done` or a drop of an entry whose session is running
    /// (§6.8: the running session is never killed).
    Running {
        /// The active entry that is running.
        id: String,
    },
    /// Verb-only: the human asked to set a daemon-owned status (`active`,
    /// `paused`, `split`) (§6.8).
    DaemonOwned {
        /// The entry whose status is daemon-owned.
        id: String,
    },
    /// Verb-only: a member called a verb §6.7 reserves to humans
    /// (§6.7 member write limits; enforced by `queue-v2-scheduling`, which
    /// owns member identity).
    MemberNotAllowed {
        /// The verb the member may not call.
        verb: String,
    },
    /// **Validation-only** (finding 9): a `slices.toml` whose `milestone`
    /// field names a different folder than the file was read from — the file
    /// belongs somewhere else, or was hand-moved. No §6.8 code describes it.
    MilestoneMismatch {
        /// What the file's `milestone` field says.
        found: String,
        /// The folder identity the file was read as.
        expected: String,
    },
    /// **Validation-only** (finding 9): a `[[item]]` row violates the §3.3
    /// item shape — `follow_ups` is slice-only, so a slice row must carry it
    /// and a `sub` row must not.
    InvalidItemShape {
        /// The item's id.
        id: String,
    },
}

impl QueueRefusal {
    /// The wire code, matching the §6.8 refusal names one for one. keeperd
    /// replies with this string (plus the payload) rather than a free-form
    /// message.
    pub fn code(&self) -> &'static str {
        match self {
            QueueRefusal::Exists { .. } => "exists",
            QueueRefusal::BadName { .. } => "bad_name",
            QueueRefusal::UnknownProject { .. } => "unknown_project",
            QueueRefusal::UnknownId { .. } => "unknown_id",
            QueueRefusal::LinkCycle { .. } => "link_cycle",
            QueueRefusal::LinkedFrom { .. } => "linked_from",
            QueueRefusal::LaneMismatch { .. } => "lane_mismatch",
            QueueRefusal::Started { .. } => "started",
            QueueRefusal::Running { .. } => "running",
            QueueRefusal::DaemonOwned { .. } => "daemon_owned",
            QueueRefusal::MemberNotAllowed { .. } => "member_not_allowed",
            QueueRefusal::MilestoneMismatch { .. } => "milestone_mismatch",
            QueueRefusal::InvalidItemShape { .. } => "invalid_item_shape",
        }
    }
}

impl fmt::Display for QueueRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueRefusal::Exists { id } => write!(f, "exists: '{id}' already exists"),
            QueueRefusal::BadName { name } => {
                write!(f, "bad_name: '{name}' is not an acceptable name")
            }
            QueueRefusal::UnknownProject { project } => {
                write!(f, "unknown_project: no project named '{project}'")
            }
            QueueRefusal::UnknownId { id } => write!(
                f,
                "unknown_id: '{id}' names no live entry and no done-archived row"
            ),
            QueueRefusal::LinkCycle { id } => {
                write!(f, "link_cycle: '{id}' lies on an after-link cycle")
            }
            QueueRefusal::LinkedFrom { id } => {
                write!(f, "linked_from: live after-links still name '{id}'")
            }
            QueueRefusal::LaneMismatch { id } => {
                write!(f, "lane_mismatch: '{id}' violates lane placement")
            }
            QueueRefusal::Started { id } => write!(
                f,
                "started: '{id}' is already active or paused, or its repo has one"
            ),
            QueueRefusal::Running { id } => {
                write!(f, "running: '{id}' is running a session right now")
            }
            QueueRefusal::DaemonOwned { id } => {
                write!(f, "daemon_owned: '{id}' is a daemon-owned status")
            }
            QueueRefusal::MemberNotAllowed { verb } => {
                write!(f, "member_not_allowed: '{verb}' is not allowed to members")
            }
            QueueRefusal::MilestoneMismatch { found, expected } => write!(
                f,
                "milestone_mismatch: the file claims '{found}', the folder is '{expected}'"
            ),
            QueueRefusal::InvalidItemShape { id } => write!(
                f,
                "invalid_item_shape: item '{id}' violates the §3.3 slice/sub follow_ups shape"
            ),
        }
    }
}

impl QueueToml {
    /// Validate every file-checkable §3.1 writer invariant against the
    /// archive, in the invariant list's order. `Ok(())` means keeperd may
    /// load and schedule from this file; any `Err` is fail-closed.
    ///
    /// 1. urgent entries precede normal ones, and every restack row is urgent;
    /// 2. ids are unique across the live file and the archive;
    /// 3. every `after` id resolves in the live file or an archive row with
    ///    final status `done`, and the link graph has no cycle (live edges
    ///    only — an archived row's own links are history);
    /// 4. every entry's project exists in the projects table;
    /// 5. at most one normal-lane entry per repo carries `active` or `paused`.
    ///
    /// Invariant 6 (remote entries never get an opencode member) is not file
    /// state — see the module docs.
    pub fn validate(&self, archive: &QueueArchiveToml) -> Result<(), QueueRefusal> {
        // 1. Lane order, and restack rows are always urgent (§3.1, §8).
        let mut seen_normal = false;
        for e in &self.entries {
            if e.kind == EntryKind::Restack && e.lane != Lane::Urgent {
                return Err(QueueRefusal::LaneMismatch { id: e.id.clone() });
            }
            if e.lane == Lane::Urgent && seen_normal {
                return Err(QueueRefusal::LaneMismatch { id: e.id.clone() });
            }
            if e.lane == Lane::Normal {
                seen_normal = true;
            }
        }

        // 2. Ids unique across the live file and the archive (the union, so an
        //    archive-internal duplicate is refused too).
        let mut seen: HashSet<&str> =
            HashSet::with_capacity(self.entries.len() + archive.entries.len());
        for id in self
            .entries
            .iter()
            .map(|e| e.id.as_str())
            .chain(archive.entries.iter().map(|a| a.row.id.as_str()))
        {
            if !seen.insert(id) {
                return Err(QueueRefusal::Exists { id: id.to_string() });
            }
        }

        // 3. after-links resolve (live or done-archived), then the live graph
        //    is acyclic.
        let live: HashMap<&str, usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| (e.id.as_str(), i))
            .collect();
        let done: HashSet<&str> = archive
            .entries
            .iter()
            .filter(|a| a.final_status == FinalStatus::Done)
            .map(|a| a.row.id.as_str())
            .collect();
        for e in &self.entries {
            for link in &e.after {
                if !live.contains_key(link.as_str()) && !done.contains(link.as_str()) {
                    return Err(QueueRefusal::UnknownId { id: link.clone() });
                }
            }
        }
        let mut state = vec![0u8; self.entries.len()];
        for i in 0..self.entries.len() {
            if let Some(cycle) = dfs_cycle(i, &self.entries, &live, &mut state) {
                return Err(QueueRefusal::LinkCycle {
                    id: self.entries[cycle].id.clone(),
                });
            }
        }

        // 4. + 5. Every project exists; one normal-lane active/paused entry
        // per repo at most. Two projects may name the same repo, so the bound
        // groups by repo path, as the invariant says ("per repo").
        let repo_of: HashMap<&str, &str> = self
            .projects
            .iter()
            .map(|p| (p.name.as_str(), p.repo.as_str()))
            .collect();
        let mut started_in_repo: HashMap<&str, &str> = HashMap::new();
        for e in &self.entries {
            let Some(repo) = repo_of.get(e.project.as_str()) else {
                return Err(QueueRefusal::UnknownProject {
                    project: e.project.clone(),
                });
            };
            if e.lane == Lane::Normal
                && matches!(e.status, EntryStatus::Active | EntryStatus::Paused)
                && started_in_repo.insert(repo, e.id.as_str()).is_some()
            {
                return Err(QueueRefusal::Started { id: e.id.clone() });
            }
        }

        Ok(())
    }
}

/// DFS over live `after` edges; returns an entry index on the cycle when a
/// back edge is found. Edges to archive rows are already checked as `done`
/// sinks and are not followed (an archived row's own links are history).
fn dfs_cycle(
    idx: usize,
    entries: &[Entry],
    live: &HashMap<&str, usize>,
    state: &mut [u8],
) -> Option<usize> {
    // 0 = unvisited, 1 = on the current stack, 2 = done.
    match state[idx] {
        1 => return Some(idx),
        2 => return None,
        _ => {}
    }
    state[idx] = 1;
    for link in &entries[idx].after {
        if let Some(&next) = live.get(link.as_str()) {
            if let Some(cycle) = dfs_cycle(next, entries, live, state) {
                return Some(cycle);
            }
        }
    }
    state[idx] = 2;
    None
}

impl SlicesToml {
    /// Validate a `slices.toml` read from the folder named `expected`
    /// (a sub-milestone passes `"<parent>/<sub-slug>"`, §3.3):
    ///
    /// - the `milestone` field matches the expected folder identity;
    /// - item ids are unique;
    /// - kind/status sit in the closed vocabularies — structurally guaranteed
    ///   by the enums at parse time, so nothing to re-check here;
    /// - `follow_ups >= 0` — the `u64` type guarantees it; the shape that
    ///   remains checkable is §3.3's "slice only": a slice row must carry
    ///   `follow_ups` and a `sub` row must not.
    pub fn validate(&self, expected: &str) -> Result<(), QueueRefusal> {
        if self.milestone != expected {
            return Err(QueueRefusal::MilestoneMismatch {
                found: self.milestone.clone(),
                expected: expected.to_string(),
            });
        }
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.items.len());
        for item in &self.items {
            if !seen.insert(item.id.as_str()) {
                return Err(QueueRefusal::Exists { id: item.id.clone() });
            }
            match (item.kind, &item.follow_ups) {
                (SliceKind::Slice, None) | (SliceKind::Sub, Some(_)) => {
                    return Err(QueueRefusal::InvalidItemShape { id: item.id.clone() });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// The §3.3 nesting bound: a milestone id nests at most 2 deep below its
/// top-level milestone (`…/subs/<a>/subs/<b>/`), so `"<top>"` (0), `"<top>/<sub>"`
/// (1) and `"<top>/<sub>/<sub>"` (2) are allowed and anything deeper is
/// refused. A helper for `slice_insert` (slice 006), not a whole-file check:
/// the milestone id passed to the verb is checked before the write.
pub fn sub_depth(milestone: &str) -> Result<(), QueueRefusal> {
    if milestone.matches('/').count() >= 3 {
        return Err(QueueRefusal::BadName {
            name: milestone.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str, repo: &str) -> super::super::Project {
        super::super::Project {
            name: name.to_string(),
            repo: repo.to_string(),
            main: "main".to_string(),
        }
    }

    fn softfig_project() -> super::super::Project {
        project("softfig", "~/projects/software-config_garden/codebase/main")
    }

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.to_string(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".to_string(),
            lane: Lane::Normal,
            status: EntryStatus::Queued,
            after: vec![],
            added: "2026-10-11T15:04:00Z".to_string(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
        }
    }

    fn archive_done(id: &str) -> super::super::ArchivedEntry {
        super::super::ArchivedEntry {
            row: entry(id),
            finished: "2026-10-11T16:00:00Z".to_string(),
            final_status: FinalStatus::Done,
            reason: None,
        }
    }

    fn archive_dropped(id: &str) -> super::super::ArchivedEntry {
        super::super::ArchivedEntry {
            row: entry(id),
            finished: "2026-10-11T16:00:00Z".to_string(),
            final_status: FinalStatus::Dropped,
            reason: Some("superseded".to_string()),
        }
    }

    fn queue(projects: Vec<super::super::Project>, entries: Vec<Entry>) -> QueueToml {
        QueueToml::new(projects, entries)
    }

    fn archive(entries: Vec<super::super::ArchivedEntry>) -> QueueArchiveToml {
        QueueArchiveToml::new(entries)
    }

    fn item(kind: SliceKind, id: &str) -> super::super::SliceItem {
        super::super::SliceItem {
            kind,
            id: id.to_string(),
            status: super::super::SliceStatus::Queued,
            follow_ups: (kind == SliceKind::Slice).then_some(0),
        }
    }

    fn slices(milestone: &str, items: Vec<super::super::SliceItem>) -> SlicesToml {
        SlicesToml::new(milestone.to_string(), items)
    }

    // -- §3.1 invariant 1: lane order + restack always urgent ----------------

    #[test]
    fn urgent_must_precede_normal() {
        let mut u = entry("urgent-a");
        u.lane = Lane::Urgent;
        let err = queue(vec![softfig_project()], vec![entry("normal-a"), u])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::LaneMismatch { id: "urgent-a".into() });
    }

    #[test]
    fn urgent_before_normal_is_ok() {
        let mut u = entry("urgent-a");
        u.lane = Lane::Urgent;
        queue(vec![softfig_project()], vec![u, entry("normal-a")])
            .validate(&archive(vec![]))
            .expect("urgent first is valid");
    }

    #[test]
    fn restack_must_be_urgent() {
        let mut r = entry("r-001");
        r.kind = EntryKind::Restack;
        r.branch = String::new();
        let err = queue(vec![softfig_project()], vec![r])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::LaneMismatch { id: "r-001".into() });
    }

    #[test]
    fn restack_in_the_urgent_lane_is_ok() {
        let mut r = entry("r-001");
        r.kind = EntryKind::Restack;
        r.lane = Lane::Urgent;
        r.branch = String::new();
        queue(vec![softfig_project()], vec![r])
            .validate(&archive(vec![]))
            .expect("an urgent restack is valid");
    }

    // -- §3.1 invariant 2: ids unique across live file + archive -------------

    #[test]
    fn duplicate_id_in_the_live_file_refused() {
        let err = queue(vec![softfig_project()], vec![entry("dup"), entry("dup")])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::Exists { id: "dup".into() });
    }

    #[test]
    fn duplicate_id_across_live_and_archive_refused() {
        let err = queue(vec![softfig_project()], vec![entry("dup")])
            .validate(&archive(vec![archive_done("dup")]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::Exists { id: "dup".into() });
    }

    #[test]
    fn duplicate_id_inside_the_archive_refused() {
        // The invariant is uniqueness across the union; two archived rows
        // sharing an id fail even when no live entry carries it.
        let err = queue(vec![softfig_project()], vec![entry("live")])
            .validate(&archive(vec![archive_done("dup"), archive_done("dup")]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::Exists { id: "dup".into() });
    }

    // -- §3.1 invariant 3: after-links resolve, graph acyclic ----------------

    #[test]
    fn after_link_to_a_live_entry_is_ok() {
        let mut a = entry("a");
        a.after = vec!["b".into()];
        queue(vec![softfig_project()], vec![a, entry("b")])
            .validate(&archive(vec![]))
            .expect("live link ok");
    }

    #[test]
    fn after_link_to_a_done_archive_row_is_ok() {
        let mut a = entry("a");
        a.after = vec!["old".into()];
        queue(vec![softfig_project()], vec![a])
            .validate(&archive(vec![archive_done("old")]))
            .expect("done archive link ok");
    }

    #[test]
    fn after_link_to_nowhere_refused() {
        let mut a = entry("a");
        a.after = vec!["ghost".into()];
        let err = queue(vec![softfig_project()], vec![a])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::UnknownId { id: "ghost".into() });
    }

    #[test]
    fn after_link_to_a_dropped_archive_row_refused() {
        // A dropped row satisfies no links (§3.2), so the link resolves to
        // nothing and fails like an unknown id.
        let mut a = entry("a");
        a.after = vec!["gone".into()];
        let err = queue(vec![softfig_project()], vec![a])
            .validate(&archive(vec![archive_dropped("gone")]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::UnknownId { id: "gone".into() });
    }

    #[test]
    fn self_link_is_a_cycle() {
        let mut a = entry("a");
        a.after = vec!["a".into()];
        let err = queue(vec![softfig_project()], vec![a])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::LinkCycle { id: "a".into() });
    }

    #[test]
    fn two_entry_cycle_refused() {
        let mut a = entry("a");
        a.after = vec!["b".into()];
        let mut b = entry("b");
        b.after = vec!["a".into()];
        let err = queue(vec![softfig_project()], vec![a, b])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::LinkCycle { id: "a".into() });
    }

    #[test]
    fn a_diamond_is_not_a_cycle() {
        let mut a = entry("a");
        a.after = vec!["b".into(), "c".into()];
        let mut b = entry("b");
        b.after = vec!["d".into()];
        let mut c = entry("c");
        c.after = vec!["d".into()];
        queue(vec![softfig_project()], vec![a, b, c, entry("d")])
            .validate(&archive(vec![]))
            .expect("a diamond is acyclic");
    }

    #[test]
    fn archived_rows_own_links_are_not_followed() {
        // An archived row is history: its own after-field could even point
        // back at a live entry without forming a cycle, because validation
        // only walks live edges.
        let mut a = entry("a");
        a.after = vec!["old".into()];
        let mut old = entry("old");
        old.after = vec!["a".into()];
        let arch = super::super::ArchivedEntry {
            row: old,
            finished: "2026-10-11T16:00:00Z".to_string(),
            final_status: FinalStatus::Done,
            reason: None,
        };
        queue(vec![softfig_project()], vec![a])
            .validate(&archive(vec![arch]))
            .expect("archive links are not followed");
    }

    // -- §3.1 invariant 4: every project exists ------------------------------

    #[test]
    fn unknown_project_refused() {
        let mut e = entry("a");
        e.project = "nope".into();
        let err = queue(vec![softfig_project()], vec![e])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::UnknownProject { project: "nope".into() });
    }

    // -- §3.1 invariant 5: one active/paused normal-lane entry per repo ------

    #[test]
    fn two_active_in_the_same_repo_refused() {
        let mut a = entry("a");
        a.status = EntryStatus::Active;
        let mut b = entry("b");
        b.status = EntryStatus::Active;
        let err = queue(vec![softfig_project()], vec![a, b])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::Started { id: "b".into() });
    }

    #[test]
    fn active_and_paused_in_the_same_repo_refused() {
        let mut a = entry("a");
        a.status = EntryStatus::Active;
        let mut b = entry("b");
        b.status = EntryStatus::Paused;
        let err = queue(vec![softfig_project()], vec![a, b])
            .validate(&archive(vec![]))
            .unwrap_err();
        assert_eq!(err, QueueRefusal::Started { id: "b".into() });
    }

    #[test]
    fn active_in_different_repos_is_ok() {
        let mut a = entry("a");
        a.status = EntryStatus::Active;
        let mut b = entry("b");
        b.status = EntryStatus::Active;
        b.project = "other".into();
        queue(
            vec![softfig_project(), project("other", "host:other-repo")],
            vec![a, b],
        )
        .validate(&archive(vec![]))
        .expect("one active per repo");
    }

    #[test]
    fn urgent_active_alongside_normal_active_in_the_same_repo_is_ok() {
        // The bound is normal-lane only (§3.1): an urgent entry running
        // alongside a normal one in the same repo is fine.
        let mut a = entry("a");
        a.status = EntryStatus::Active;
        let mut b = entry("b");
        b.status = EntryStatus::Active;
        b.lane = Lane::Urgent;
        queue(vec![softfig_project()], vec![b, a])
            .validate(&archive(vec![]))
            .expect("urgent + normal active ok");
    }

    #[test]
    fn two_projects_sharing_a_repo_share_the_started_bound() {
        // The invariant groups by repo path, so a second project naming the
        // same repo cannot start a second entry either.
        let mut a = entry("a");
        a.status = EntryStatus::Active;
        let mut b = entry("b");
        b.status = EntryStatus::Active;
        b.project = "mirror".into();
        let err = queue(
            vec![
                softfig_project(),
                project("mirror", "~/projects/software-config_garden/codebase/main"),
            ],
            vec![a, b],
        )
        .validate(&archive(vec![]))
        .unwrap_err();
        assert_eq!(err, QueueRefusal::Started { id: "b".into() });
    }

    // -- claims are not a file invariant -------------------------------------

    #[test]
    fn a_claimed_queued_entry_still_validates() {
        // A hand-seeded claimed row: claims are scheduling state, not a file
        // invariant. The started/running refusals are verb-level (slices
        // 005–006).
        let mut e = entry("a");
        e.claimed = "2026-10-11T09:00:00Z".into();
        e.parent = "parent-entry".into();
        e.base = "abc123".into();
        queue(vec![softfig_project()], vec![e])
            .validate(&archive(vec![]))
            .expect("claimed-queued is valid");
    }

    #[test]
    fn an_empty_queue_validates() {
        queue(vec![], vec![])
            .validate(&archive(vec![]))
            .expect("an empty queue is valid");
    }

    // -- SlicesToml::validate -------------------------------------------------

    #[test]
    fn duplicate_slice_item_id_refused() {
        let err = slices(
            "m",
            vec![item(SliceKind::Slice, "001"), item(SliceKind::Slice, "001")],
        )
        .validate("m")
        .unwrap_err();
        assert_eq!(err, QueueRefusal::Exists { id: "001".into() });
    }

    #[test]
    fn milestone_field_must_match_the_folder() {
        let err = slices("other", vec![item(SliceKind::Slice, "001")])
            .validate("folder-grants")
            .unwrap_err();
        assert_eq!(
            err,
            QueueRefusal::MilestoneMismatch {
                found: "other".into(),
                expected: "folder-grants".into(),
            }
        );
    }

    #[test]
    fn a_slice_missing_follow_ups_refused() {
        let mut it = item(SliceKind::Slice, "001");
        it.follow_ups = None;
        let err = slices("m", vec![it]).validate("m").unwrap_err();
        assert_eq!(
            err,
            QueueRefusal::InvalidItemShape { id: "001".into() }
        );
    }

    #[test]
    fn a_sub_carrying_follow_ups_refused() {
        let mut it = item(SliceKind::Sub, "sub-a");
        it.follow_ups = Some(0);
        let err = slices("m", vec![it]).validate("m").unwrap_err();
        assert_eq!(
            err,
            QueueRefusal::InvalidItemShape { id: "sub-a".into() }
        );
    }

    #[test]
    fn mixed_slices_and_subs_validate() {
        slices(
            "m",
            vec![
                item(SliceKind::Slice, "001"),
                item(SliceKind::Sub, "sub-a"),
                item(SliceKind::Slice, "002"),
            ],
        )
        .validate("m")
        .expect("mixed items are valid");
    }

    #[test]
    fn a_sub_milestone_identity_matches_with_a_path() {
        slices("fid/gate", vec![item(SliceKind::Slice, "001")])
            .validate("fid/gate")
            .expect("sub-milestone identity ok");
    }

    // -- sub_depth (§3.3 nesting bound) ---------------------------------------

    #[test]
    fn sub_depth_allows_two_levels_and_refuses_three() {
        for ok in ["m", "m/a", "m/a/b"] {
            sub_depth(ok).expect("within the §3.3 nesting bound");
        }
        assert_eq!(
            sub_depth("m/a/b/c").unwrap_err(),
            QueueRefusal::BadName {
                name: "m/a/b/c".into()
            }
        );
    }

    // -- refusal constructors, one test each ---------------------------------

    #[test]
    fn refusal_exists() {
        let r = QueueRefusal::Exists { id: "x".into() };
        assert_eq!(r.code(), "exists");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_bad_name() {
        let r = QueueRefusal::BadName { name: "x".into() };
        assert_eq!(r.code(), "bad_name");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_unknown_project() {
        let r = QueueRefusal::UnknownProject { project: "x".into() };
        assert_eq!(r.code(), "unknown_project");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_unknown_id() {
        let r = QueueRefusal::UnknownId { id: "x".into() };
        assert_eq!(r.code(), "unknown_id");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_link_cycle() {
        let r = QueueRefusal::LinkCycle { id: "x".into() };
        assert_eq!(r.code(), "link_cycle");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_linked_from() {
        let r = QueueRefusal::LinkedFrom { id: "x".into() };
        assert_eq!(r.code(), "linked_from");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_lane_mismatch() {
        let r = QueueRefusal::LaneMismatch { id: "x".into() };
        assert_eq!(r.code(), "lane_mismatch");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_started() {
        let r = QueueRefusal::Started { id: "x".into() };
        assert_eq!(r.code(), "started");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_running() {
        let r = QueueRefusal::Running { id: "x".into() };
        assert_eq!(r.code(), "running");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_daemon_owned() {
        let r = QueueRefusal::DaemonOwned { id: "x".into() };
        assert_eq!(r.code(), "daemon_owned");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn refusal_member_not_allowed() {
        let r = QueueRefusal::MemberNotAllowed { verb: "queue_drop".into() };
        assert_eq!(r.code(), "member_not_allowed");
        assert!(r.to_string().contains("queue_drop"));
    }

    #[test]
    fn refusal_milestone_mismatch() {
        let r = QueueRefusal::MilestoneMismatch {
            found: "x".into(),
            expected: "y".into(),
        };
        assert_eq!(r.code(), "milestone_mismatch");
        assert!(r.to_string().contains("x") && r.to_string().contains("y"));
    }

    #[test]
    fn refusal_invalid_item_shape() {
        let r = QueueRefusal::InvalidItemShape { id: "x".into() };
        assert_eq!(r.code(), "invalid_item_shape");
        assert!(r.to_string().contains("x"));
    }

    #[test]
    fn every_refusal_round_trips_through_the_wire() {
        // The refusals cross the IPC wire, so every variant must survive a
        // serde round-trip with its payload intact.
        let cases = [
            QueueRefusal::Exists { id: "x".into() },
            QueueRefusal::BadName { name: "x".into() },
            QueueRefusal::UnknownProject { project: "x".into() },
            QueueRefusal::UnknownId { id: "x".into() },
            QueueRefusal::LinkCycle { id: "x".into() },
            QueueRefusal::LinkedFrom { id: "x".into() },
            QueueRefusal::LaneMismatch { id: "x".into() },
            QueueRefusal::Started { id: "x".into() },
            QueueRefusal::Running { id: "x".into() },
            QueueRefusal::DaemonOwned { id: "x".into() },
            QueueRefusal::MemberNotAllowed { verb: "queue_drop".into() },
            QueueRefusal::MilestoneMismatch {
                found: "x".into(),
                expected: "y".into(),
            },
            QueueRefusal::InvalidItemShape { id: "x".into() },
        ];
        for refusal in cases {
            let json = serde_json::to_string(&refusal).expect("serialize");
            let back: QueueRefusal = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, refusal, "round-trip for {}", refusal.code());
        }
    }
}
