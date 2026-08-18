//! mcp-surgical-writes slice 005 — `batch`, the atomic multi-op commit
//! (spec: `meta/spec-mcp-writes/spec-batch.md`).
//!
//! One logical garden change is rarely one file — "add a note, bump the map's
//! cross-refs, stamp a reviewed date" is three commits today. `batch` composes
//! N whitelisted sub-ops into ONE `batch_applied` commit: the atomicity
//! primitive for multi-file logical changes.
//!
//! ## Two-phase (the atomicity contract)
//!
//! 1. **Validate everything first.** Each sub-op is parsed against its own
//!    typed `*Args` shape and run through the same read-only checks its
//!    standalone verb enforces (path validation + `.softfig/` refusal, vault
//!    refusal, whole-file / section CAS, uniqueness + managed-region checks),
//!    all against a **simulated working state** — an in-memory overlay of the
//!    files the batch touches — so op N validates against op N−1's *result*
//!    (ordered, sequential semantics) without a single write having landed.
//!    Any failure aborts with nothing staged and the error names the failing
//!    op index + kind. (Disk mode hits the real FS on `wt.write`, so this
//!    validation pass MUST complete before the first write.)
//! 2. **Stage, then commit once.** The mutations land in op order through the
//!    [`WorkTree`] (the `.seq` bump + doc for `add_note`, the plain rewrite for
//!    the rest), folder indexes refresh for every accretive folder an
//!    add/revise touched (deferred to after all op writes so a later op's
//!    write to the same `CLAUDE.md` composes instead of clobbering), the
//!    backlink graph refreshes once, and ONE [`commit_now`] mints the
//!    `batch_applied` intent with a compact `{ops: [{op, path}]}` payload.
//!
//! ## Whitelist (v1)
//!
//! `patch_file`, `edit_section`, `append_to_section`, `add_section`,
//! `remove_section`, `set_reviewed`, `add_note`, `revise_note`. Deliberately
//! excluded: `unlink` (a batch that deletes is a different safety review),
//! `batch` itself (no nesting), the convention-heavy log/archive/add_project
//! family (their intents are single-file by design), and everything growlight.
//! `revise_note` is gated to the note folders (`notes`/`troubleshooting`) —
//! the code-review genre stays out of v1 alongside `add_code_review`.
//!
//! Thrash: the batch registers one edit touch per mutated (file, section) for
//! the op kinds whose standalone verbs do (`patch_file` whole-file,
//! edit/append/remove section) — the batch's `editor` propagates to each.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use softfig_ipc::verbs::{
    AddNoteArgs, AddSectionArgs, AppendToSectionArgs, BatchArgs, BatchOp, BatchReply,
    EditSectionArgs, PatchFileArgs, RemoveSectionArgs, ReviseNoteArgs, SetReviewedArgs,
};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::sections::{
    cas_check_section, edit, load_unprotected, note_edit_for_thrash, resolve, section_err,
};
use super::{commit_now, conventions, numbering, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{
    path_to_repo_rel_string, require_unlocked, validate_repo_path, HandlerResult,
};

/// The v1 sub-op whitelist — the file-mutation family (see module docs).
const WHITELIST: &[&str] = &[
    "patch_file",
    "edit_section",
    "append_to_section",
    "add_section",
    "remove_section",
    "set_reviewed",
    "add_note",
    "revise_note",
];

/// A validated, ready-to-stage mutation. The content carried here is exactly
/// what validation computed over the simulated state, so staging can never
/// diverge from what was checked.
enum Mutation {
    /// Rewrite one existing file with the computed content.
    Write { rel: String, content: String },
    /// `add_note`: bump `.seq` to `number` and write the stamped doc.
    AddNote {
        dir_rel: String,
        number: u32,
        note_rel: String,
        content: String,
    },
    /// `revise_note`: overwrite the existing numbered doc.
    ReviseNote {
        dir_rel: String,
        note_rel: String,
        content: String,
    },
}

struct Staged {
    mutation: Mutation,
    /// The `{op, path}` payload row for the `batch_applied` intent.
    op_name: &'static str,
    path: String,
    /// The contention-detector touch this op registers, if its standalone verb
    /// registers one: `(file, section)` — `None` heading = whole-file.
    thrash: Option<(String, Option<String>)>,
}

/// The simulated working state of the validation pass: op N reads through this
/// overlay (falling back to the live working tree), so it validates against
/// op N−1's result while nothing has been staged yet.
struct Sim {
    /// file → content after the ops applied so far.
    files: BTreeMap<String, String>,
    /// accretive folder → the NEXT number an `add_note` to it gets (lazily
    /// seeded from the live `.seq`/listing, incremented per simulated add).
    next: BTreeMap<String, u32>,
    /// notes added by earlier ops: (dir_rel, number, note_rel, stamped content)
    /// — `revise_note`'s `find_by_id` fallback for notes created in-batch.
    added: Vec<(String, u32, String, String)>,
}

/// Read `rel`'s content through the simulation overlay — the working-tree
/// bytes (with the full vault refusal of [`load_unprotected`]) the first time
/// a path is touched, the simulated post-ops content after that.
fn sim_content(
    daemon: &Daemon,
    inner: &DaemonInner,
    sim: &mut Sim,
    rel: &str,
) -> Result<String, (ErrorKind, String)> {
    if let Some(c) = sim.files.get(rel) {
        return Ok(c.clone());
    }
    let wt = WorkTree::new(daemon, inner);
    let content = load_unprotected(&wt, inner, rel)?;
    sim.files.insert(rel.to_string(), content.clone());
    Ok(content)
}

/// Whole-file CAS against the simulated content (the standalone guard reads
/// the live working tree; in a batch the guard must see op N−1's result).
fn sim_cas_whole_file(
    sim: &Sim,
    rel: &str,
    expected: &Option<String>,
) -> Result<(), (ErrorKind, String)> {
    if let Some(want) = expected {
        let cur = sim
            .files
            .get(rel)
            .map(|c| softfig_store::Hash::of(c.as_bytes()).to_hex());
        if cur.as_deref() != Some(want.as_str()) {
            return Err((
                ErrorKind::Conflict,
                format!("stale: {rel} changed since version {want} — re-read and retry"),
            ));
        }
    }
    Ok(())
}

/// The `add_note`/`revise_note` dir gate + resolution, shared by both sub-ops:
/// validate `dir` against the garden root and require an accretive note folder
/// (the code-review genre stays out of batch v1 alongside `add_code_review`).
fn resolve_note_dir(
    garden_root: &Path,
    dir: &str,
) -> Result<String, (ErrorKind, String)> {
    let dir_abs = validate_repo_path(garden_root, dir).map_err(|m| (ErrorKind::BadArgs, m))?;
    let dir_rel = path_to_repo_rel_string(garden_root, &dir_abs)
        .ok_or((ErrorKind::BadArgs, "dir outside garden root".into()))?;
    if !conventions::dir_basename_in(&dir_rel, &conventions::NOTE_FOLDERS) {
        return Err((
            ErrorKind::NotAccretiveDir,
            format!(
                "{dir_rel}: notes live only in an accretive folder (notes / troubleshooting)"
            ),
        ));
    }
    Ok(dir_rel)
}

pub fn batch(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: BatchArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("batch args: {e}")))?;
    if args.ops.is_empty() {
        return Err((ErrorKind::BadArgs, "ops must be non-empty".into()));
    }
    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    // ---- phase 1: validate EVERY op before anything is staged -------------
    // All checks are read-only (the WorkTree reads / the pure transform cores)
    // and run against the simulated state, so a failure here leaves the
    // working tree byte-identical to when the batch arrived.
    let mut sim = Sim {
        files: BTreeMap::new(),
        next: BTreeMap::new(),
        added: Vec::new(),
    };
    let mut staged: Vec<Staged> = Vec::new();
    for (i, op) in args.ops.iter().enumerate() {
        validate_op(daemon, &inner, &garden_root, op, &mut sim, &mut staged).map_err(
            |(kind, msg)| (kind, format!("batch op[{i}] ({}) failed: {msg}", op.op)),
        )?;
    }

    // ---- phase 2: stage the mutations in order, then one commit -----------
    // The staged contents are exactly what validation computed, so this phase
    // cannot hit a validation-class failure — only the same IO-failure tail
    // the standalone verbs share (which fails the verb before any commit).
    {
        let wt = WorkTree::new(daemon, &inner);
        for s in &staged {
            match &s.mutation {
                Mutation::Write { rel, content } => wt.write(rel, content.as_bytes())?,
                Mutation::AddNote {
                    dir_rel,
                    number,
                    note_rel,
                    content,
                } => numbering::write_numbered(&wt, dir_rel, *number, note_rel, content)?,
                Mutation::ReviseNote { note_rel, content, .. } => {
                    wt.write(note_rel, content.as_bytes())?;
                }
            }
        }
        // Folder index refreshes are DEFERRED past every op write: they are
        // region-scoped rewrites of the parent CLAUDE.md, so a later op's
        // write to that same file composes with them instead of clobbering
        // (the interleave would also invalidate the simulated content the
        // later op validated against). Deduped, first-touch order.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for s in &staged {
            let dir_rel = match &s.mutation {
                Mutation::AddNote { dir_rel, .. } | Mutation::ReviseNote { dir_rel, .. } => {
                    dir_rel.as_str()
                }
                Mutation::Write { .. } => continue,
            };
            if seen.insert(dir_rel) {
                super::index::refresh_folder_index(&wt, &inner, dir_rel);
            }
        }
        // A batch can add/remove `[[…]]` refs across any of its writes, so
        // recompute the backlink graph once, over the final staged state.
        super::backlinks::refresh_all(&wt, &inner);
    }

    let payload_ops: Vec<serde_json::Value> = staged
        .iter()
        .map(|s| serde_json::json!({ "op": s.op_name, "path": s.path }))
        .collect();
    let intent = Intent::new("batch_applied", serde_json::json!({ "ops": payload_ops }))
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    // Thrash: one touch per mutated (file, section), editor propagated.
    let mut touched: BTreeSet<(String, Option<String>)> = BTreeSet::new();
    for (rel, heading) in staged.iter().filter_map(|s| s.thrash.clone()) {
        if touched.insert((rel.clone(), heading.clone())) {
            note_edit_for_thrash(daemon, inner, &rel, heading.as_deref(), args.editor.as_deref());
        }
    }

    let mut paths: Vec<String> = Vec::new();
    let mut seen_paths: BTreeSet<&str> = BTreeSet::new();
    for s in &staged {
        if seen_paths.insert(s.path.as_str()) {
            paths.push(s.path.clone());
        }
    }
    Ok(serde_json::to_value(BatchReply {
        hash: hash.to_string(),
        ops: staged.len(),
        paths,
    })
    .unwrap())
}

/// Validate one sub-op against the simulation and append its staged mutation.
/// Every failure names the sub-op's own error precisely; the caller prefixes
/// the op index + kind.
fn validate_op(
    daemon: &Daemon,
    inner: &DaemonInner,
    garden_root: &Path,
    op: &BatchOp,
    sim: &mut Sim,
    staged: &mut Vec<Staged>,
) -> Result<(), (ErrorKind, String)> {
    if !WHITELIST.contains(&op.op.as_str()) {
        return Err((
            ErrorKind::BadArgs,
            format!(
                "{} is not a batch sub-op — whitelist: {}",
                op.op,
                WHITELIST.join(", ")
            ),
        ));
    }
    match op.op.as_str() {
        "patch_file" => {
            let a: PatchFileArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("patch_file args: {e}")))?;
            if a.old.is_empty() {
                return Err((ErrorKind::BadArgs, "old must be non-empty".into()));
            }
            if a.anchor.as_deref().is_some_and(str::is_empty) {
                return Err((
                    ErrorKind::BadArgs,
                    "anchor must be non-empty when provided (omit it to search the whole file)"
                        .into(),
                ));
            }
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            sim_cas_whole_file(sim, &rel, &a.expected_version)?;
            let new = super::patch_file::core::patch(&content, &a.old, &a.new, a.anchor.as_deref())
                .map_err(|e| super::patch_file::patch_err(&rel, &a.old, a.anchor.as_deref(), e))?;
            sim.files.insert(rel.clone(), new.clone());
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "patch_file",
                path: rel.clone(),
                thrash: Some((rel, None)),
            });
        }
        "edit_section" => {
            let a: EditSectionArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("edit_section args: {e}")))?;
            if a.body.trim().is_empty() {
                return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
            }
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            cas_check_section(&content, &a.heading, &a.expected_version)?;
            let new = edit::edit_section(&content, &a.heading, &a.body)
                .map_err(|e| section_err(&rel, &a.heading, e))?;
            sim.files.insert(rel.clone(), new.clone());
            let heading_text = edit::parse_heading_arg(&a.heading).1;
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "edit_section",
                path: rel.clone(),
                thrash: Some((rel, Some(heading_text))),
            });
        }
        "append_to_section" => {
            let a: AppendToSectionArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("append_to_section args: {e}")))?;
            if a.text.trim().is_empty() {
                return Err((ErrorKind::BadArgs, "text must be non-empty".into()));
            }
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            cas_check_section(&content, &a.heading, &a.expected_version)?;
            let new = edit::append_to_section(&content, &a.heading, &a.text)
                .map_err(|e| section_err(&rel, &a.heading, e))?;
            sim.files.insert(rel.clone(), new.clone());
            let heading_text = edit::parse_heading_arg(&a.heading).1;
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "append_to_section",
                path: rel.clone(),
                thrash: Some((rel, Some(heading_text))),
            });
        }
        "add_section" => {
            let a: AddSectionArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("add_section args: {e}")))?;
            if a.body.trim().is_empty() {
                return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
            }
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            let new = edit::add_section(&content, &a.heading, &a.body)
                .map_err(|e| section_err(&rel, &a.heading, e))?;
            sim.files.insert(rel.clone(), new.clone());
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "add_section",
                path: rel,
                thrash: None,
            });
        }
        "remove_section" => {
            let a: RemoveSectionArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("remove_section args: {e}")))?;
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            cas_check_section(&content, &a.heading, &a.expected_version)?;
            // Same managed-region guard as the standalone verb: never delete
            // through a daemon-managed index region.
            let (rstart, rend) = edit::section_range(&content, &a.heading)
                .map_err(|e| section_err(&rel, &a.heading, e))?;
            if let Some(tag) = super::managed::overlapping_region(&content, rstart, rend) {
                return Err((
                    ErrorKind::BadArgs,
                    format!(
                        "{rel}: section {:?} overlaps the daemon-managed <!-- softfig:{tag} --> \
                         region — regenerate that region through its owning machinery, not by hand",
                        a.heading
                    ),
                ));
            }
            let new = edit::remove_section(&content, &a.heading)
                .map_err(|e| section_err(&rel, &a.heading, e))?;
            sim.files.insert(rel.clone(), new.clone());
            let heading_text = edit::parse_heading_arg(&a.heading).1;
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "remove_section",
                path: rel.clone(),
                thrash: Some((rel, Some(heading_text))),
            });
        }
        "set_reviewed" => {
            let a: SetReviewedArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("set_reviewed args: {e}")))?;
            let rel = resolve(garden_root, &a.path)?;
            let content = sim_content(daemon, inner, sim, &rel)?;
            let new = edit::set_reviewed(&content, &conventions::today_hyphen()).ok_or((
                ErrorKind::NotFound,
                format!("{rel}: no 'Last reviewed:' line to stamp"),
            ))?;
            sim.files.insert(rel.clone(), new.clone());
            staged.push(Staged {
                mutation: Mutation::Write {
                    rel: rel.clone(),
                    content: new,
                },
                op_name: "set_reviewed",
                path: rel,
                thrash: None,
            });
        }
        "add_note" => {
            let a: AddNoteArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("add_note args: {e}")))?;
            conventions::validate_slug(&a.slug)?;
            if a.body.trim().is_empty() {
                return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
            }
            let dir_rel = resolve_note_dir(garden_root, &a.dir)?;
            let wt = WorkTree::new(daemon, inner);
            // The concept dir must exist (the standalone verb materializes the
            // accretive folder on demand, but won't fabricate an arbitrary tree).
            let parent_rel = Path::new(&dir_rel).parent().and_then(|p| p.to_str()).unwrap_or("");
            if !wt.is_dir(parent_rel) {
                return Err((
                    ErrorKind::NotFound,
                    format!("{dir_rel}: parent concept dir does not exist"),
                ));
            }
            // Sequential numbering: the first add to a folder seeds from the
            // live `.seq`/listing, each further add in the batch takes the next.
            let number = *sim
                .next
                .entry(dir_rel.clone())
                .or_insert_with(|| numbering::next_number(&wt, &dir_rel));
            *sim.next.get_mut(&dir_rel).unwrap() += 1;
            let filename = conventions::note_filename(number, &a.slug);
            let note_rel = format!("{dir_rel}/{filename}");
            if wt.exists(&note_rel) {
                return Err((ErrorKind::PathAlreadyExists, format!("{note_rel}: already exists")));
            }
            let content = conventions::note_doc(
                a.title.as_deref().unwrap_or(&a.slug),
                &conventions::today_hyphen(),
                &a.body,
            );
            sim.added
                .push((dir_rel.clone(), number, note_rel.clone(), content.clone()));
            staged.push(Staged {
                mutation: Mutation::AddNote {
                    dir_rel,
                    number,
                    note_rel: note_rel.clone(),
                    content,
                },
                op_name: "add_note",
                path: note_rel,
                thrash: None,
            });
        }
        "revise_note" => {
            let a: ReviseNoteArgs = serde_json::from_value(op.args.clone())
                .map_err(|e| (ErrorKind::BadArgs, format!("revise_note args: {e}")))?;
            if a.body.trim().is_empty() {
                return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
            }
            let dir_rel = resolve_note_dir(garden_root, &a.dir)?;
            let wt = WorkTree::new(daemon, inner);
            // A note added earlier in the batch resolves from the simulation;
            // anything else must already be live in the folder.
            let (note_rel, existing) = match sim
                .added
                .iter()
                .find(|(d, id, _, _)| d == &dir_rel && *id == a.id)
            {
                Some((_, _, rel, content)) => (rel.clone(), content.clone()),
                None => {
                    let rel = numbering::find_by_id(&wt, &dir_rel, a.id).ok_or((
                        ErrorKind::NotFound,
                        format!("{dir_rel}: no note numbered {:03}", a.id),
                    ))?;
                    let existing = wt.read_to_string(&rel).ok_or((
                        ErrorKind::Io,
                        format!("read {rel}: not found"),
                    ))?;
                    (rel, existing)
                }
            };
            // Preserve the title (immutable); the daemon re-stamps the reviewed
            // date and swaps the body, like the standalone verb.
            let filename = Path::new(&note_rel)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("note.md");
            let title = conventions::note_title(&existing)
                .unwrap_or_else(|| conventions::slug_from_note_name(filename));
            let content = conventions::note_doc(&title, &conventions::today_hyphen(), &a.body);
            staged.push(Staged {
                mutation: Mutation::ReviseNote {
                    dir_rel,
                    note_rel: note_rel.clone(),
                    content,
                },
                op_name: "revise_note",
                path: note_rel,
                thrash: None,
            });
        }
        _ => unreachable!("whitelist checked above"),
    }
    Ok(())
}
