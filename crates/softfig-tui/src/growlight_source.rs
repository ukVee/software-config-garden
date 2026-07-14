//! The `GrowlightSource` read seam — a logical growlight *artifact* → concrete
//! *read* resolver.
//!
//! Every growlight artifact the detail pane displays is fetched through this
//! seam instead of hard-coding a path or verb at the call site. Two arms:
//! * the **garden-read arm** (slice 002): in-garden artifacts (backlog, slices,
//!   loop-context docs) resolve to a keeperd `read_file` at a repo-relative path;
//! * the **growlightd arm** (slice 004): the runtime baton — which lives *outside*
//!   the garden today — resolves to the growlightd `baton` read verb.
//!
//! The seam exists for the planned runtime-FUSE-mount (milestone
//! `growlight-tui-detail-pane` `## Forward-compat`): when the growlight runtime
//! (baton, injected context) is mounted as a garden chain, the runtime artifacts
//! re-point from the growlightd arm to garden reads at the mount path — a source
//! swap here, with no change to the tree/viewer code, and the `baton` verb retires.
//!
//! Pure — no IO — so the artifact → read mapping is fully unit-testable.

use std::collections::HashMap;

use softfig_ipc::TreeEntry;

/// A logical growlight artifact the detail pane can display. The file-like
/// variants below already live in the garden and resolve to garden reads today;
/// runtime artifacts (`runtime-baton`, `injected-protocol`, …) are added in
/// later slices and route to a growlightd verb until the runtime is mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrowlightArtifact {
    /// A milestone's `CLAUDE.md` (its body + managed slice index).
    Milestone { id: String },
    /// A standalone backlog task, keyed by its bare `NNN` queue id (its file is
    /// `NNN-slug.md`, so the resolver needs the tasks dir listing).
    Task { id: String },
    /// A slice file at a known full garden path — the backlog tree already
    /// resolves a slice row's link target to a full path.
    Slice { path: String },
    /// A loop-context doc read verbatim from the garden (`protocol.md`,
    /// `protocol-fleet.md`, `session-policy.md`, the pillar `CLAUDE.md`).
    LoopContext { path: String },
    /// The LIVE fleet/legacy single-agent runtime baton — out-of-garden today, so
    /// it routes to the growlightd `baton` verb (slice 004). Retires when the
    /// runtime is a mounted garden chain (`## Forward-compat`).
    RuntimeBaton,
    /// A specific fleet member's live baton (`agents/<id>/baton.md`) — likewise via
    /// the growlightd `baton` verb, carrying the member id (slice 004).
    MemberBaton { id: String },
}

/// The concrete read an artifact resolves to: a keeperd garden read, or the
/// growlightd `baton` verb for the out-of-garden runtime baton (slice 004). The
/// growlightd arm retires when the runtime is a mounted garden chain — the runtime
/// artifacts then re-point to `Garden` reads at the mount path (`## Forward-compat`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrowlightRead {
    /// A keeperd garden `read_file` at this repo-relative path.
    Garden { path: String },
    /// A growlightd `baton` verb call: `agent: None` = the fleet/legacy runtime
    /// baton, `Some(id)` = that member's baton. Transitional (see the enum doc).
    Growlightd { agent: Option<String> },
}

/// Resolves logical artifacts to reads. Holds the bare-`NNN` → full-path map for
/// standalone tasks, rebuilt from a `list_tree growlight/backlog/tasks` listing.
#[derive(Debug, Default)]
pub struct GrowlightSource {
    /// Bare task id (`NNN`) → full garden path (`growlight/backlog/tasks/NNN-slug.md`).
    task_paths: HashMap<String, String>,
}

impl GrowlightSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the tasks dir listing: map each `NNN-slug.md` file to its bare
    /// `NNN` id so a `Task { id }` artifact resolves to the full garden path.
    /// Directories and non-`NNN`-prefixed entries are ignored.
    pub fn set_task_paths(&mut self, entries: &[TreeEntry]) {
        self.task_paths = entries
            .iter()
            .filter(|e| !e.is_dir)
            .filter_map(|e| {
                let num = e.name.split('-').next()?;
                if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                Some((num.to_string(), e.path.clone()))
            })
            .collect();
    }

    /// Map an artifact to its concrete read. `None` when a task's path is not yet
    /// known (its dir listing hasn't arrived) — the caller retries on the listing.
    pub fn resolve(&self, artifact: &GrowlightArtifact) -> Option<GrowlightRead> {
        let path = match artifact {
            GrowlightArtifact::Milestone { id } => {
                format!("growlight/backlog/milestones/{id}/CLAUDE.md")
            }
            GrowlightArtifact::Task { id } => self.task_paths.get(id)?.clone(),
            GrowlightArtifact::Slice { path } => path.clone(),
            GrowlightArtifact::LoopContext { path } => path.clone(),
            // Runtime artifacts route to the growlightd `baton` verb, not a garden
            // read — the transitional arm that retires on the runtime FUSE mount.
            GrowlightArtifact::RuntimeBaton => {
                return Some(GrowlightRead::Growlightd { agent: None })
            }
            GrowlightArtifact::MemberBaton { id } => {
                return Some(GrowlightRead::Growlightd { agent: Some(id.clone()) })
            }
        };
        Some(GrowlightRead::Garden { path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, path: &str, is_dir: bool) -> TreeEntry {
        TreeEntry {
            name: name.to_string(),
            path: path.to_string(),
            is_dir,
        }
    }

    #[test]
    fn milestone_resolves_to_its_claude_md() {
        let src = GrowlightSource::new();
        assert_eq!(
            src.resolve(&GrowlightArtifact::Milestone {
                id: "m5c-union-mount".into()
            }),
            Some(GrowlightRead::Garden {
                path: "growlight/backlog/milestones/m5c-union-mount/CLAUDE.md".into()
            })
        );
    }

    #[test]
    fn slice_and_loop_context_pass_their_path_through() {
        let src = GrowlightSource::new();
        assert_eq!(
            src.resolve(&GrowlightArtifact::Slice {
                path: "growlight/backlog/milestones/m/slices/002-x.md".into()
            }),
            Some(GrowlightRead::Garden {
                path: "growlight/backlog/milestones/m/slices/002-x.md".into()
            })
        );
        assert_eq!(
            src.resolve(&GrowlightArtifact::LoopContext {
                path: "growlight/protocol.md".into()
            }),
            Some(GrowlightRead::Garden {
                path: "growlight/protocol.md".into()
            })
        );
    }

    #[test]
    fn task_resolves_via_the_dir_listing_bare_id_to_full_path() {
        let mut src = GrowlightSource::new();
        // A task before its listing arrives can't resolve.
        assert_eq!(src.resolve(&GrowlightArtifact::Task { id: "042".into() }), None);

        src.set_task_paths(&[
            entry("CLAUDE.md", "growlight/backlog/tasks/CLAUDE.md", false),
            entry(
                "042-fleet-driveloop-stall.md",
                "growlight/backlog/tasks/042-fleet-driveloop-stall.md",
                false,
            ),
            entry("subdir", "growlight/backlog/tasks/subdir", true),
        ]);
        assert_eq!(
            src.resolve(&GrowlightArtifact::Task { id: "042".into() }),
            Some(GrowlightRead::Garden {
                path: "growlight/backlog/tasks/042-fleet-driveloop-stall.md".into()
            })
        );
        // A non-existent id still yields nothing.
        assert_eq!(src.resolve(&GrowlightArtifact::Task { id: "999".into() }), None);
    }

    #[test]
    fn runtime_baton_artifacts_route_to_the_growlightd_verb_not_a_garden_read() {
        // The slice-004 growlightd arm: the runtime baton is out-of-garden, so it
        // resolves to the `baton` verb (agent None), never a `Garden` read.
        let src = GrowlightSource::new();
        assert_eq!(
            src.resolve(&GrowlightArtifact::RuntimeBaton),
            Some(GrowlightRead::Growlightd { agent: None })
        );
        // A per-member baton carries the agent id onto the verb.
        assert_eq!(
            src.resolve(&GrowlightArtifact::MemberBaton { id: "a".into() }),
            Some(GrowlightRead::Growlightd { agent: Some("a".into()) })
        );
    }

    #[test]
    fn set_task_paths_ignores_non_numeric_and_dir_entries() {
        let mut src = GrowlightSource::new();
        src.set_task_paths(&[
            entry("CLAUDE.md", "growlight/backlog/tasks/CLAUDE.md", false),
            entry("notes", "growlight/backlog/tasks/notes", true),
            entry("readme.md", "growlight/backlog/tasks/readme.md", false),
        ]);
        // None of those are `NNN-`-prefixed files → no task resolves.
        assert_eq!(src.resolve(&GrowlightArtifact::Task { id: "".into() }), None);
    }
}
