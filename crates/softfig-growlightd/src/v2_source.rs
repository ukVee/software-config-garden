//! The v2 queue **source** (queue-v2-scheduling slice 003): growlightd's
//! reader of the three TOML files that hold the v2 backlog, reduced to the
//! [`V2Snapshot`](crate::scheduler_v2::V2Snapshot) the pure
//! [`pick_v2`](crate::scheduler_v2::pick_v2) consumes. Spec:
//! `meta/spec-growlight-queue.md` §3 (state: where the lists live) and §12
//! (the queue-reading seam).
//!
//! ## The read path
//!
//! growlightd is keeperd's client, so it reads the v2 files **through the
//! FUSE mount** — the same client-side plain read
//! [`load_fleet_config`](crate::fleet::load_fleet_config) uses for
//! `config/growlight.toml` — never through a keeperd socket. Paths come from
//! the `softfig-ipc` constants and [`milestone_path`] / [`slices_file`]
//! (finding 10's single translation), so the reader side and keeperd's writer
//! side can never disagree about where a file lives.
//!
//! ## Fail-closed, alert-once
//!
//! §3: an invalid or unreadable file means **growlightd schedules nothing from
//! v2 and alerts once**. [`V2Source::load`] is the per-tick seam: it returns
//! [`V2Load::Failed`] with `alert: true` only on the first tick an error is
//! seen (or when the error changes), and `alert: false` while the same error
//! persists — the once-per-incident alert with no on-disk state (in-memory
//! only, the eMMC rule). A recovery resets the memory, so a later breakage
//! alerts again.
//!
//! Absence is not an error, matching keeperd's loaders: no `queue.toml` means
//! there is no v2 state yet ([`V2Load::Absent`]), and a milestone without a
//! `slices.toml` simply contributes no tree — the unit walk then reports
//! `NoUnit` for it, never a guessed close-out (slice 002's contract).
//!
//! ## What gets resolved here (slice 002's snapshot contract)
//!
//! - **`> Model:` declarations** are resolved once at assembly, per unit, via
//!   [`item_doc_candidates`] + [`resolve_item_models`]: a slice's own doc,
//!   then each enclosing sub-milestone's `CLAUDE.md` innermost-first, then the
//!   milestone's `CLAUDE.md`; a task/restack's own doc for its unit. `None` =
//!   undeclared → the member default (§6.4). **A malformed declaration is
//!   fail-closed** ([`V2SourceError::InvalidModelDecl`]): the declaration
//!   gates which backend may run the unit, so silently treating a broken one
//!   as "undeclared" would let any member take explicitly gated work. The
//!   alert names the doc to fix. (Design completion, recorded in the slice
//!   doc — §3 only names the TOML files.)
//! - **`holder`** is runtime state (active → the running member, paused → the
//!   pauser), which growlightd knows only at the moment it happens — so the
//!   source fills `None` everywhere and the drive loop (slice 006) overlays
//!   it.
//! - **`done_ids`** collects only archive rows with `final_status = done`; a
//!   `dropped` row is absent by construction, so it never satisfies an
//!   `after` link (§2).
//! - **Trees** are loaded for every live milestone entry, recursing into each
//!   `sub` item's own `slices.toml` (§3.3), bounded by [`sub_depth`] — a sub
//!   nesting deeper than two levels is an invalid file, refused here rather
//!   than walked past.
//!
//! ## What is deliberately not here
//!
//! No scheduling (slice 002), no keeperd socket, and no wiring into the drive
//! loop — that is slice 006, behind the §11 switch. This module exists so
//! slice 006 just plugs a `V2Source` in.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use softfig_ipc::model_choice::{item_doc_candidates, resolve_item_models, ModelList};
use softfig_ipc::queue_v2::{
    slices_file, sub_depth, EntryKind, FinalStatus, QueueArchiveToml, QueueRefusal, QueueToml,
    QueueV2Error, SliceKind, SlicesToml, QUEUE_ARCHIVE_FILE, QUEUE_FILE,
};

use crate::scheduler_v2::{EntryView, ItemView, ProjectView, TreeView, V2Snapshot};

/// A v2 file (or its model-declaration chain) that exists but could not be
/// read, parsed, or validated. Every variant is typed and carries the
/// garden-relative file it came from. There is no fallback: any `Err` means
/// growlightd schedules nothing from v2 (§3).
#[derive(Debug)]
pub enum V2SourceError {
    /// The file exists but could not be read as plaintext (an I/O error — a
    /// sealed file parses as garbage instead and lands in [`InvalidToml`]).
    Unreadable { rel: String, cause: String },
    /// Does not parse as the file it claims to be: malformed TOML, a missing
    /// or unknown field, a value outside a closed vocabulary, or a schema
    /// this build does not write.
    InvalidToml { rel: String, source: QueueV2Error },
    /// Parses, but violates a §3.1/§3.3 writer invariant.
    InvalidState { rel: String, refusal: QueueRefusal },
    /// A doc in the unit's §6.4 chain declares a `> Model:` line that does
    /// not parse. `context` names the unit; the message names the declaring
    /// doc.
    InvalidModelDecl { context: String, message: String },
}

impl fmt::Display for V2SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { rel, cause } => write!(f, "{rel}: unreadable ({cause})"),
            Self::InvalidToml { rel, source } => write!(f, "{rel}: {source}"),
            Self::InvalidState { rel, refusal } => write!(f, "{rel}: {refusal}"),
            Self::InvalidModelDecl { context, message } => {
                write!(f, "{context}: invalid `> Model:` declaration ({message})")
            }
        }
    }
}

impl std::error::Error for V2SourceError {}

/// One tick's verdict from [`V2Source::load`] — the fail-closed answer the
/// drive loop (slice 006) switches on.
#[derive(Debug)]
pub enum V2Load {
    /// The v2 list exists and validated; the snapshot is ready for `pick_v2`.
    Snapshot(V2Snapshot),
    /// No `queue.toml` — there is no v2 state yet (§3.4: a view renders only
    /// when its TOML exists). Schedule nothing, alert nothing.
    Absent,
    /// A file was invalid or unreadable: schedule nothing from v2. `alert`
    /// is `true` only on the first tick of this error (or when the error
    /// changes) — §3's "alerts once".
    Failed { error: V2SourceError, alert: bool },
}

/// The live v2 source: [`assemble`] the snapshot from the mount each tick,
/// with the in-memory alert-once state. Constructed by the drive loop (slice
/// 006) with the garden root; `load` takes `&mut self` because it owns the
/// alert memory.
#[derive(Debug)]
pub struct V2Source {
    garden_root: PathBuf,
    /// The rendered error currently being alerted-on: `None` after any
    /// successful or absent read, so a recovery resets the once-per-incident
    /// memory. Kept as text because [`V2SourceError`] is not `Clone` (its
    /// `QueueV2Error` carries a `toml` error) — and the rendered form is the
    /// same deterministic identity two ticks of one broken file share.
    last_error: Option<String>,
}

impl V2Source {
    /// Bind the source to a garden root (the FUSE mount path in production).
    pub fn new(garden_root: PathBuf) -> Self {
        Self {
            garden_root,
            last_error: None,
        }
    }

    /// One tick's v2 read: assemble the snapshot, and apply the §3
    /// fail-closed + alert-once semantics. A `Snapshot` or `Absent` clears
    /// the error memory; a repeated `Failed` with the same error stays quiet.
    pub fn load(&mut self) -> V2Load {
        match assemble(&self.garden_root) {
            Ok(Some(snapshot)) => {
                self.last_error = None;
                V2Load::Snapshot(snapshot)
            }
            Ok(None) => {
                self.last_error = None;
                V2Load::Absent
            }
            Err(error) => {
                let rendered = error.to_string();
                let alert = self.last_error.as_deref() != Some(rendered.as_str());
                if alert {
                    eprintln!(
                        "growlightd: v2 queue source failed (scheduling nothing from v2): \
                         {error}"
                    );
                }
                self.last_error = Some(rendered);
                V2Load::Failed { error, alert }
            }
        }
    }
}

/// The drive loop's [`V2QueueSource`](crate::drive_loop::V2QueueSource) seam
/// (queue-v2-scheduling slice 006): the concrete source IS the seam — `load` is
/// the same per-tick method, including the `&mut self` alert memory. The
/// explicit inherent call disambiguates from the trait method of the same name.
impl crate::drive_loop::V2QueueSource for V2Source {
    fn load(&mut self) -> V2Load {
        V2Source::load(self)
    }
}

/// Read + parse + validate the v2 state under `garden_root` and assemble the
/// snapshot slice 002's `pick_v2` consumes. `Ok(None)` = no `queue.toml` (no
/// v2 state yet); any `Err` is fail-closed — the caller schedules nothing and
/// alerts (once, via [`V2Source`]).
///
/// Reads, in order: `queue.toml` and `queue-archive.toml` (§3.1–§3.2, the
/// archive is what `after` links and id uniqueness validate against), then
/// every live milestone entry's `slices.toml` (§3.3), recursing into `sub`
/// items' own trees, each validated against its folder identity. A milestone
/// whose `slices.toml` is absent contributes no tree — the unit walk then
/// reports `NoUnit` for it (never a guessed close-out).
pub fn assemble(garden_root: &Path) -> Result<Option<V2Snapshot>, V2SourceError> {
    let Some(queue_raw) = read_v2_file(garden_root, QUEUE_FILE)? else {
        return Ok(None);
    };
    let queue = QueueToml::parse(&queue_raw).map_err(|source| V2SourceError::InvalidToml {
        rel: QUEUE_FILE.to_string(),
        source,
    })?;

    // The archive is optional on disk: no file means nothing has left the
    // list yet, which is an empty archive (and validates as one).
    let archive = match read_v2_file(garden_root, QUEUE_ARCHIVE_FILE)? {
        Some(text) => QueueArchiveToml::parse(&text).map_err(|source| {
            V2SourceError::InvalidToml {
                rel: QUEUE_ARCHIVE_FILE.to_string(),
                source,
            }
        })?,
        None => QueueArchiveToml::new(Vec::new()),
    };

    // The §3.1 writer invariants, against the archive.
    queue
        .validate(&archive)
        .map_err(|refusal| V2SourceError::InvalidState {
            rel: QUEUE_FILE.to_string(),
            refusal,
        })?;

    let projects = queue
        .projects
        .iter()
        .map(|p| ProjectView {
            name: p.name.clone(),
            repo: p.repo.clone(),
        })
        .collect();

    let mut entries: Vec<EntryView> = Vec::with_capacity(queue.entries.len());
    let mut trees: BTreeMap<String, TreeView> = BTreeMap::new();
    for entry in &queue.entries {
        let models = match entry.kind {
            // A task or restack is its own unit (§4): its allowed list is
            // just its doc's chain.
            EntryKind::Task | EntryKind::Restack => {
                resolve_chain(garden_root, &entry.id, None)?
            }
            // A milestone's units resolve inside its tree; the entry itself
            // carries no list.
            EntryKind::Milestone => {
                load_tree(garden_root, &entry.id, &mut trees)?;
                None
            }
        };
        entries.push(EntryView {
            id: entry.id.clone(),
            kind: entry.kind,
            project: entry.project.clone(),
            lane: entry.lane,
            status: entry.status,
            after: entry.after.clone(),
            claimed: entry.claimed.clone(),
            follow_ups: entry.follow_ups,
            // Runtime state, not TOML — the drive loop overlays it (slice
            // 006; slice 002's contract).
            holder: None,
            models,
        });
    }

    // §3.2: only `done` rows satisfy links; a `dropped` row is absent here by
    // construction.
    let done_ids: BTreeSet<String> = archive
        .entries
        .iter()
        .filter(|a| a.final_status == FinalStatus::Done)
        .map(|a| a.row.id.clone())
        .collect();

    Ok(Some(V2Snapshot {
        projects,
        entries,
        trees,
        done_ids,
    }))
}

/// Load one milestone's (or sub-milestone's) `slices.toml` into `trees` —
/// its items in file order with each slice's resolved `> Model:` list, then
/// the tree's own chain-resolved list (the close-out unit's, §6.4). Recurses
/// into `sub` items, bounded by the §3.3 two-level nesting ([`sub_depth`]); a
/// deeper sub is an invalid file, refused. An absent `slices.toml` inserts
/// nothing — `NoUnit` territory, not a close-out.
fn load_tree(
    garden_root: &Path,
    milestone: &str,
    trees: &mut BTreeMap<String, TreeView>,
) -> Result<(), V2SourceError> {
    let rel = slices_file(milestone);
    let Some(raw) = read_v2_file(garden_root, &rel)? else {
        return Ok(());
    };
    let slices = SlicesToml::parse(&raw).map_err(|source| V2SourceError::InvalidToml {
        rel: rel.clone(),
        source,
    })?;
    slices.validate(milestone).map_err(|refusal| V2SourceError::InvalidState {
        rel: rel.clone(),
        refusal,
    })?;

    let mut items: Vec<ItemView> = Vec::with_capacity(slices.items.len());
    for item in &slices.items {
        match item.kind {
            SliceKind::Slice => {
                let models = resolve_chain(garden_root, milestone, Some(&item.id))?;
                items.push(ItemView {
                    kind: SliceKind::Slice,
                    id: item.id.clone(),
                    status: item.status,
                    models,
                    follow_ups: item.follow_ups.unwrap_or(0),
                });
            }
            SliceKind::Sub => {
                let sub_identity = format!("{milestone}/{}", item.id);
                sub_depth(&sub_identity).map_err(|refusal| V2SourceError::InvalidState {
                    rel: rel.clone(),
                    refusal,
                })?;
                load_tree(garden_root, &sub_identity, trees)?;
                items.push(ItemView {
                    kind: SliceKind::Sub,
                    id: item.id.clone(),
                    status: item.status,
                    // A sub's units resolve inside its own tree.
                    models: None,
                    follow_ups: 0,
                });
            }
        }
    }
    // The close-out unit's allowed list: the milestone's own chain.
    let models = resolve_chain(garden_root, milestone, None)?;
    trees.insert(milestone.to_string(), TreeView { items, models });
    Ok(())
}

/// Resolve a unit's chain-declared `> Model:` list (§6.4): the docs
/// [`item_doc_candidates`] names, nearest first, read through the mount. A
/// candidate that cannot be read as text (e.g. a doc that does not exist) is
/// skipped — the chain passes through it; a *malformed* declaration in a
/// readable doc is fail-closed, because treating it as "undeclared" would
/// silently drop the backend gate it was meant to be.
fn resolve_chain(
    garden_root: &Path,
    item: &str,
    slice: Option<&str>,
) -> Result<Option<ModelList>, V2SourceError> {
    let docs: Vec<(String, Option<String>)> = item_doc_candidates(garden_root, item, slice)
        .into_iter()
        .map(|path| {
            let label = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unnamed>")
                .to_string();
            let content = std::fs::read_to_string(&path).ok();
            (label, content)
        })
        .collect();
    let context = match slice {
        Some(slice) => format!("milestone \"{item}\" slice \"{slice}\""),
        None => format!("entry \"{item}\""),
    };
    match resolve_item_models(docs) {
        Ok(Some(declared)) => Ok(Some(declared.list)),
        Ok(None) => Ok(None),
        Err(e) => Err(V2SourceError::InvalidModelDecl {
            context,
            message: e.to_string(),
        }),
    }
}

/// Read one v2 file through the mount. `Ok(None)` only when the file is
/// genuinely absent (no v2 state, or no slices yet); any other read failure
/// is [`V2SourceError::Unreadable`] — fail-closed, never skipped.
fn read_v2_file(root: &Path, rel: &str) -> Result<Option<String>, V2SourceError> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(V2SourceError::Unreadable {
            rel: rel.to_string(),
            cause: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use softfig_ipc::model_choice::{parse_declaration, Declaration};
    use softfig_ipc::queue_v2::{
        Entry, EntryStatus, Lane, Project, SliceItem, SliceStatus,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A throwaway on-disk garden: `growlight/backlog/…` plus slice docs, as
    /// the live mount would serve them. Every test gets its own root (tests
    /// share a process, so a fixed name would collide).
    struct TempGarden {
        root: PathBuf,
    }

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    impl TempGarden {
        fn new() -> Self {
            let n = NEXT.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!("sf-v2-source-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create temp garden");
            Self { root }
        }

        fn root(&self) -> &Path {
            &self.root
        }

        /// Write `rel` with `content`, creating parent directories.
        fn write(&self, rel: &str, content: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dirs");
            }
            std::fs::write(&path, content).expect("write fixture file");
        }

        /// Create a *directory* where a file is expected — the unreadable
        /// case (`read_to_string` on a directory is an I/O error).
        fn write_dir(&self, rel: &str) {
            std::fs::create_dir_all(self.root.join(rel)).expect("create fixture dir");
        }
    }

    impl Drop for TempGarden {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn project(name: &str, repo: &str) -> Project {
        Project {
            name: name.into(),
            repo: repo.into(),
            main: "main".into(),
        }
    }

    fn softfig_project() -> Project {
        project("softfig", "~/projects/software-config_garden/codebase/main")
    }

    fn entry(id: &str) -> Entry {
        Entry {
            id: id.into(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".into(),
            lane: Lane::Normal,
            status: EntryStatus::Queued,
            after: vec![],
            added: "2026-10-11T15:04:00Z".into(),
            branch: format!("feat/{id}"),
            parent: String::new(),
            base: String::new(),
            claimed: String::new(),
            follow_ups: 0,
            pending_status: None,
        }
    }

    fn queue_toml(projects: Vec<Project>, entries: Vec<Entry>) -> String {
        QueueToml::new(projects, entries)
            .to_toml()
            .expect("serialize queue")
    }

    fn archive_done(id: &str) -> softfig_ipc::queue_v2::ArchivedEntry {
        softfig_ipc::queue_v2::ArchivedEntry {
            row: entry(id),
            finished: "2026-10-11T16:00:00Z".into(),
            final_status: FinalStatus::Done,
            reason: None,
        }
    }

    fn archive_dropped(id: &str) -> softfig_ipc::queue_v2::ArchivedEntry {
        softfig_ipc::queue_v2::ArchivedEntry {
            row: entry(id),
            finished: "2026-10-11T16:00:00Z".into(),
            final_status: FinalStatus::Dropped,
            reason: Some("superseded".into()),
        }
    }

    fn item(kind: SliceKind, id: &str, status: SliceStatus) -> SliceItem {
        SliceItem {
            kind,
            id: id.into(),
            status,
            follow_ups: (kind == SliceKind::Slice).then_some(0),
        }
    }

    fn slices_toml(milestone: &str, items: Vec<SliceItem>) -> String {
        SlicesToml::new(milestone.into(), items)
            .to_toml()
            .expect("serialize slices")
    }

    fn list(spec: &str) -> ModelList {
        match parse_declaration(spec).expect("parse declaration") {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list, not auto"),
        }
    }

    fn source(root: &Path) -> V2Source {
        V2Source::new(root.to_path_buf())
    }

    // -- absence --------------------------------------------------------------

    #[test]
    fn absent_queue_file_is_no_v2_state_not_an_error() {
        let garden = TempGarden::new();
        assert_eq!(assemble(garden.root()).unwrap(), None);
        // The tick seam reports Absent — no alert, no error.
        assert!(matches!(source(garden.root()).load(), V2Load::Absent));
    }

    #[test]
    fn a_milestone_without_slices_toml_contributes_no_tree() {
        // A milestone queued before its first slice is written: no
        // slices.toml. The snapshot carries the entry but no tree — the unit
        // walk reports NoUnit for it, never a guessed close-out.
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        let snapshot = assemble(garden.root()).unwrap().unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert!(
            snapshot.trees.is_empty(),
            "an absent slices.toml contributes no tree"
        );
    }

    #[test]
    fn an_empty_queue_assembles_an_empty_snapshot() {
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![], vec![]));
        let snapshot = assemble(garden.root()).unwrap().unwrap();
        assert!(snapshot.projects.is_empty() && snapshot.entries.is_empty());
        assert!(snapshot.trees.is_empty() && snapshot.done_ids.is_empty());
    }

    // -- valid assembly ---------------------------------------------------------

    #[test]
    fn a_valid_garden_assembles_lanes_links_trees_and_models() {
        let garden = TempGarden::new();

        // The list: an urgent milestone (with an after-link), a normal
        // milestone, a task. A second project for the task.
        let mut urgent = entry("urgent");
        urgent.lane = Lane::Urgent;
        urgent.after = vec!["done-one".into()];
        let mut task = entry("047");
        task.kind = EntryKind::Task;
        task.project = "other".into();
        garden.write(
            QUEUE_FILE,
            &queue_toml(
                vec![softfig_project(), project("other", "~/projects/other")],
                vec![urgent.clone(), entry("m"), task.clone()],
            ),
        );

        // The archive: one done row (satisfies the link), one dropped row
        // (never enters done_ids).
        let archive = softfig_ipc::queue_v2::QueueArchiveToml::new(vec![
            archive_done("done-one"),
            archive_dropped("dropped-one"),
        ]);
        garden.write(
            QUEUE_ARCHIVE_FILE,
            &archive.to_toml().expect("serialize archive"),
        );

        // Milestone m: slice 001 done (declares reasoning), sub s1 queued,
        // slice 003 queued with no doc of its own → the milestone CLAUDE.md.
        garden.write(
            &slices_file("m"),
            &slices_toml(
                "m",
                vec![
                    item(SliceKind::Slice, "001", SliceStatus::Done),
                    item(SliceKind::Sub, "s1", SliceStatus::Queued),
                    item(SliceKind::Slice, "003", SliceStatus::Queued),
                ],
            ),
        );
        garden.write(
            "growlight/backlog/milestones/m/slices/001-first.md",
            "> Model: reasoning\n",
        );
        // No 003-*.md at all — the chain falls to the milestone doc.
        garden.write(
            "growlight/backlog/milestones/m/CLAUDE.md",
            "# m\n\n> Model: claude\n",
        );

        // Sub s1: slice 001 queued (no decl → s1's CLAUDE.md), sub s2 done.
        garden.write(
            &slices_file("m/s1"),
            &slices_toml(
                "m/s1",
                vec![
                    item(SliceKind::Slice, "001", SliceStatus::Queued),
                    item(SliceKind::Sub, "s2", SliceStatus::Done),
                ],
            ),
        );
        garden.write(
            "growlight/backlog/milestones/m/subs/s1/CLAUDE.md",
            "# s1\n\n> Model: flash\n",
        );
        // Sub s2 (two deep, the §3.3 bound): one done slice declaring a
        // mixed list.
        garden.write(
            &slices_file("m/s1/s2"),
            &slices_toml("m/s1/s2", vec![item(SliceKind::Slice, "001", SliceStatus::Done)]),
        );
        garden.write(
            "growlight/backlog/milestones/m/subs/s1/subs/s2/slices/001-only.md",
            "> Model: reasoning, flash\n",
        );

        // The task's own doc declares flash.
        garden.write(
            "growlight/backlog/tasks/047-a-task.md",
            "> Model: flash\n",
        );

        let snapshot = assemble(garden.root()).unwrap().unwrap();

        // Projects + entries in file order.
        assert_eq!(
            snapshot
                .projects
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["softfig", "other"]
        );
        assert_eq!(
            snapshot.entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            vec!["urgent", "m", "047"],
            "file order is list order"
        );
        let urgent_view = &snapshot.entries[0];
        assert_eq!(urgent_view.lane, Lane::Urgent);
        assert_eq!(urgent_view.after, vec!["done-one".to_string()]);
        assert_eq!(urgent_view.holder, None, "holder is runtime, not TOML");
        assert_eq!(urgent_view.models, None, "a milestone entry carries no list");
        assert_eq!(snapshot.entries[1].models, None);
        let task_view = &snapshot.entries[2];
        assert_eq!(task_view.kind, EntryKind::Task);
        assert_eq!(task_view.models, Some(list("flash")), "task unit = its doc");

        // done_ids: done rows only.
        assert_eq!(
            snapshot.done_ids,
            BTreeSet::from(["done-one".to_string()]),
            "a dropped row never satisfies a link"
        );

        // Trees: the milestone, the sub, and the sub-sub — each in file order.
        assert_eq!(
            snapshot.trees.keys().cloned().collect::<Vec<_>>(),
            vec!["m", "m/s1", "m/s1/s2"]
        );
        let m = &snapshot.trees["m"];
        assert_eq!(m.items.len(), 3);
        assert_eq!(m.items[0].id, "001");
        assert_eq!(m.items[0].models, Some(list("reasoning")), "slice doc wins");
        assert_eq!(m.items[1].kind, SliceKind::Sub);
        assert_eq!(m.items[1].models, None, "a sub resolves inside its own tree");
        assert_eq!(
            m.items[2].models,
            Some(list("claude")),
            "an undeclared slice falls to the milestone CLAUDE.md"
        );
        assert_eq!(m.models, Some(list("claude")), "close-out = the milestone chain");

        let s1 = &snapshot.trees["m/s1"];
        assert_eq!(
            s1.items[0].models,
            Some(list("flash")),
            "an undeclared slice falls to the sub's CLAUDE.md"
        );
        assert_eq!(s1.models, Some(list("flash")));
        let s2 = &snapshot.trees["m/s1/s2"];
        assert_eq!(
            s2.items[0].models,
            Some(list("reasoning, flash")),
            "the two-deep sub's slice doc"
        );
    }

    // -- fail-closed cases ------------------------------------------------------

    #[test]
    fn bad_toml_fails_closed_and_alerts_exactly_once() {
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, "not toml {{{");
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::InvalidToml { .. })
        ));

        // Two ticks: the first alerts, the second is the same incident.
        let mut src = source(garden.root());
        match src.load() {
            V2Load::Failed { alert: true, .. } => {}
            other => panic!("first tick must alert, got {other:?}"),
        }
        match src.load() {
            V2Load::Failed { alert: false, .. } => {}
            other => panic!("a repeated error must stay quiet, got {other:?}"),
        }
    }

    #[test]
    fn a_future_schema_fails_closed() {
        let garden = TempGarden::new();
        let text = queue_toml(vec![softfig_project()], vec![entry("m")])
            .replace("schema = 1", "schema = 2");
        garden.write(QUEUE_FILE, &text);
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::InvalidToml { source: QueueV2Error::UnsupportedSchema { found: 2 }, .. })
        ));
    }

    #[test]
    fn a_queue_invariant_violation_fails_closed() {
        // Duplicate ids across the live file and the archive.
        let garden = TempGarden::new();
        garden.write(
            QUEUE_FILE,
            &queue_toml(vec![softfig_project()], vec![entry("dup")]),
        );
        let archive = softfig_ipc::queue_v2::QueueArchiveToml::new(vec![archive_done("dup")]);
        garden.write(
            QUEUE_ARCHIVE_FILE,
            &archive.to_toml().expect("serialize archive"),
        );
        assert!(
            assemble(garden.root()).unwrap_err().to_string().contains("exists"),
            "the Exists refusal reaches the error text"
        );
    }

    #[test]
    fn a_slices_invariant_violation_fails_closed() {
        // The file claims a different milestone than its folder.
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        garden.write(
            &slices_file("m"),
            &slices_toml("other", vec![item(SliceKind::Slice, "001", SliceStatus::Queued)]),
        );
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::InvalidState {
                refusal: QueueRefusal::MilestoneMismatch { .. },
                ..
            })
        ));
    }

    #[test]
    fn bad_slices_toml_fails_closed() {
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        garden.write(&slices_file("m"), "schema = 1\n[[item]\nkind = \"slice\"\n");
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::InvalidToml { .. })
        ));
    }

    #[test]
    fn an_unreadable_file_fails_closed() {
        // A directory at queue.toml: read_to_string errors instead of
        // parsing — the Unreadable path, no lossy skip.
        let garden = TempGarden::new();
        garden.write_dir("growlight/backlog/queue.toml");
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::Unreadable { .. })
        ));
    }

    #[test]
    fn a_sub_nesting_deeper_than_two_levels_fails_closed() {
        // m/s1/s2's tree contains a sub item → identity "m/s1/s2/x" is three
        // deep; §3.3's bound refuses it.
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        garden.write(
            &slices_file("m"),
            &slices_toml("m", vec![item(SliceKind::Sub, "s1", SliceStatus::Queued)]),
        );
        garden.write(
            &slices_file("m/s1"),
            &slices_toml("m/s1", vec![item(SliceKind::Sub, "s2", SliceStatus::Queued)]),
        );
        garden.write(
            &slices_file("m/s1/s2"),
            &slices_toml("m/s1/s2", vec![item(SliceKind::Sub, "x", SliceStatus::Queued)]),
        );
        assert!(matches!(
            assemble(garden.root()),
            Err(V2SourceError::InvalidState {
                refusal: QueueRefusal::BadName { .. },
                ..
            })
        ));
    }

    #[test]
    fn a_malformed_model_declaration_fails_closed_and_names_the_unit() {
        // The declaration gates which backend may run the unit; treating a
        // broken one as "undeclared" would drop the gate, so it is an error.
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        garden.write(
            &slices_file("m"),
            &slices_toml("m", vec![item(SliceKind::Slice, "001", SliceStatus::Queued)]),
        );
        garden.write(
            "growlight/backlog/milestones/m/slices/001-first.md",
            "> Model: gpt-9\n",
        );
        match assemble(garden.root()) {
            Err(V2SourceError::InvalidModelDecl { context, message }) => {
                assert!(
                    context.contains("\"m\"") && context.contains("\"001\""),
                    "the context names the unit: {context}"
                );
                assert!(message.contains("001-first.md"), "the message names the doc");
            }
            other => panic!("must be InvalidModelDecl, got {other:?}"),
        }
    }

    // -- the alert memory --------------------------------------------------------

    #[test]
    fn recovery_resets_the_alert_and_a_new_error_alerts_again() {
        let garden = TempGarden::new();
        garden.write(QUEUE_FILE, "not toml {{{");

        let mut src = source(garden.root());
        assert!(matches!(src.load(), V2Load::Failed { alert: true, .. }));
        assert!(matches!(src.load(), V2Load::Failed { alert: false, .. }));

        // Fix the queue, break the slices instead: a new incident, so a new
        // alert.
        garden.write(QUEUE_FILE, &queue_toml(vec![softfig_project()], vec![entry("m")]));
        garden.write(&slices_file("m"), "also not toml {{{");
        assert!(matches!(src.load(), V2Load::Failed { alert: true, .. }));
        assert!(matches!(src.load(), V2Load::Failed { alert: false, .. }));

        // Fully fixed: the snapshot flows, and the memory is clear.
        garden.write(
            &slices_file("m"),
            &slices_toml("m", vec![item(SliceKind::Slice, "001", SliceStatus::Queued)]),
        );
        assert!(matches!(src.load(), V2Load::Snapshot(_)));
        // Breaking again later alerts again.
        garden.write(QUEUE_FILE, "schema = 99");
        assert!(matches!(src.load(), V2Load::Failed { alert: true, .. }));
    }
}
