//! Folder grants ([[spec-growlight-grants]]) — the per-item allowed-folder
//! model: parse `> Grants:` and `> Worktree:` lines, expand variables,
//! canonicalize, check the ceiling, and resolve an ordered list per spawn.
//!
//! Pure code; nothing calls it yet (slice 002 wires it into growlightd's
//! spawn, slice 003 into the opencode floor builder, slice 005 into the
//! `softfig growlight grants` dry run). It shares the item-doc chain walk
//! with the model resolver through [`crate::item_meta`] — one scanner, two
//! readers.
//!
//! A grant lands in the resolved list by **last match wins** (§5):
//! 1. the project default (`rw $WORKTREE` if the item declares one, else
//!    `rw $REPO`);
//! 2. the milestone (or sub-milestone chain, outer → inner) `> Grants:` lines;
//! 3. the slice `> Grants:` lines.
//!
//! A later entry overrides an earlier one on the same canonical path; a slice
//! `rw`/`ro` entry on a path step 1–2 did not already cover in that mode or
//! stronger is flagged `widened` so the human can see it in status (§3).
//! Every `rw` entry over a git checkout is followed by an implicit
//! `deny <checkout>/.git` for file-tool edits (§5 git-dir guard).
//!
//! Every refusal in [`GrantError`] parks the spawn (§8). A grant error is
//! deterministic — a retry would repeat it — so growlightd never re-rolls one.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::item_meta;
use crate::model_choice::Backend;

/// One of the three grant modes (§3): `rw` (read + write), `ro` (read only), or
/// `deny` (neither — used to carve a hole out of a wider grant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Rw,
    Ro,
    Deny,
}

impl Mode {
    /// How a resolver line names the mode in errors and `grants.md`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Rw => "rw",
            Mode::Ro => "ro",
            Mode::Deny => "deny",
        }
    }

    /// Access level for the widening check (§5): `rw` grants read + write, `ro`
    /// grants read, `deny` grants nothing. A slice `rw`/`ro` entry whose path
    /// is a step-1/2 path OR a path below one, at a mode whose access level is
    /// at or above the slice entry's, is not widened — step-1/2 already covers
    /// the access the slice is asking for.
    fn access_level(self) -> u8 {
        match self {
            Mode::Rw => 2,
            Mode::Ro => 1,
            Mode::Deny => 0,
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a grant was declared, for status and refusal messages (§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The declaring doc's label (e.g. `005-picker.md`, `CLAUDE.md`,
    /// `tasks/047-a-task.md`), matching the chain labels the caller passed.
    pub doc: String,
    /// 1-indexed line number of the `> Grants:` line in `doc`, or `0` for the
    /// synthetic project default (which has no declaring line).
    pub line: usize,
    /// A short tag for status output: `queue default` / `milestone` / `slice`.
    pub tier: Tier,
}

/// Which resolution tier a resolved [`Grant`] came from (§5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The synthetic `rw $WORKTREE` / `rw $REPO` default (§5 step 1).
    ProjectDefault,
    /// A `> Grants:` line on the milestone, sub-milestone chain, or task doc
    /// (§5 step 2).
    MilestoneOrTask,
    /// A `> Grants:` line on the slice doc (§5 step 3).
    Slice,
    /// A synthetic `deny <checkout>/.git` appended after an `rw` over a git
    /// checkout (§5 git-dir guard).
    GitGuard,
    /// A trailing `deny` from the ceiling (§6, defense in depth).
    CeilingDeny,
}

impl Tier {
    /// The one-word label `grants.md` and `growlight status` print.
    pub fn label(self) -> &'static str {
        match self {
            Tier::ProjectDefault => "queue default",
            Tier::MilestoneOrTask => "milestone",
            Tier::Slice => "slice",
            Tier::GitGuard => "git guard",
            Tier::CeilingDeny => "ceiling",
        }
    }
}

/// A resolved grant (§5): a mode on a canonical path, with its origin and the
/// widened flag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub mode: Mode,
    pub path: PathBuf,
    pub origin: Origin,
    /// True when a slice `rw`/`ro` entry's path and mode were not already
    /// covered by a step-1/2 entry at that mode or stronger (§3, §5).
    /// `growlight status` surfaces it; a human cross-check for scope creep.
    pub widened: bool,
}

/// Every fail-closed refusal in [[spec-growlight-grants]] §5. Each one parks
/// the spawn and alerts once (§8); it is never dropped, defaulted or retried.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// A `> Grants:` entry did not parse as `<mode> <path>` or had an unknown
    /// mode. The spec's one parse error (§5).
    #[error("{origin}: `> Grants:` entry {entry_index} does not parse: {reason}")]
    Parse {
        origin: Origin,
        entry_index: usize,
        reason: String,
    },

    /// A `> Worktree:` line appeared on a slice doc. §4: `> Worktree:` is
    /// allowed on milestones and tasks only.
    #[error("{origin}: `> Worktree:` is not allowed on a slice doc")]
    WorktreeOnSlice { origin: Origin },

    /// A grant path uses `$<name>` for a name we do not know (§5
    /// "unknown or unresolvable variable").
    #[error("{origin}: `> Grants:` entry {entry_index}: unknown variable `${name}` in `{path}`")]
    UnknownVariable {
        origin: Origin,
        entry_index: usize,
        name: String,
        path: String,
    },

    /// A grant path uses a known variable whose source is absent at this spawn
    /// (`$REPO` on an item whose project has no local repo, or `$WORKTREE` on
    /// an item whose doc chain declares no `> Worktree:`). §5.
    #[error("{origin}: `> Grants:` entry {entry_index}: `${name}` is not set — {reason}")]
    UnresolvableVariable {
        origin: Origin,
        entry_index: usize,
        name: String,
        reason: String,
        path: String,
    },

    /// A grant path is not absolute after variable expansion. §3: relative
    /// paths are refused.
    #[error("{origin}: `> Grants:` entry {entry_index}: `{path}` is not absolute")]
    RelativePath {
        origin: Origin,
        entry_index: usize,
        path: String,
    },

    /// A grant path contains `*`, `?`, or a control character. §3: wildcards
    /// would widen the grant past the directory named through opencode's
    /// matcher.
    #[error("{origin}: `> Grants:` entry {entry_index}: `{path}` contains disallowed character `{bad}`")]
    IllegalChar {
        origin: Origin,
        entry_index: usize,
        path: String,
        bad: char,
    },

    /// A grant path hits the ceiling: equal to, inside, or ancestor of a
    /// ceiling entry (§6).
    #[error(
        "{origin}: `> Grants:` entry {entry_index}: `{path}` hits the ceiling (relation {relation:?} to `{entry}`)"
    )]
    CeilingHit {
        origin: Origin,
        entry_index: usize,
        path: String,
        entry: String,
        relation: CeilingRelation,
    },

    /// A grant path is not under one of the allowed grantable roots (§6:
    /// "Grantable roots are only paths under `$HOME`, or under `/tmp/<name>/`
    /// (not `/tmp` itself)"). `/`, bare `$HOME`, bare `/tmp`, and anywhere
    /// outside those two trees refuse here.
    #[error(
        "{origin}: `> Grants:` entry {entry_index}: `{path}` is not under an allowed grantable root (`$HOME` or `/tmp/<name>/`)"
    )]
    UngrantableRoot {
        origin: Origin,
        entry_index: usize,
        path: String,
    },

    /// A `> Worktree:` path exists but is not a git worktree of `$REPO` (§4).
    #[error("`> Worktree:` {worktree} is not a worktree of $REPO {repo}")]
    WorktreeNotOfRepo { worktree: String, repo: String },

    /// A `> Worktree:` path does not exist and its parent directory does not
    /// exist either (§4).
    #[error("`> Worktree:` parent `{parent}` does not exist for `{worktree}`")]
    WorktreeParentMissing { worktree: String, parent: String },

    /// `$REPO` is a remote (`host:path`) repo and the member runs on opencode
    /// (§9). ssh runs through the unbounded shell, which this layer does not
    /// gate; the opencode spawn is refused instead.
    #[error("opencode member assigned a remote-project entry (`$REPO` = `{repo}`)")]
    RemoteRepoOnOpencode { repo: String },
}

/// How a grant path related to a ceiling entry at refusal (§6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeilingRelation {
    /// `path == entry` — a grant on the ceiling entry itself.
    Equal,
    /// `path` is inside `entry` — a grant below a ceiling root.
    Inside,
    /// `path` is an ancestor of `entry` — a wide grant that would cover a
    /// ceiling root (`ro ~/.config` covers `~/.config/opencode`).
    AncestorOf,
}

/// How an item's project binds to a local repo (§4). `Remote` carries the raw
/// `host:path` value for messages; the resolver refuses the spawn when it sees
/// a remote repo on an opencode backend (§9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectRepo<'a> {
    /// A local absolute path (expanded, canonical not required).
    Local(&'a Path),
    /// A remote `host:path` value.
    Remote(&'a str),
    /// No `$REPO` for this item — a legacy default-queue item whose queue has
    /// no registry row (§1, §4). An `rw $REPO` default is omitted; a grant line
    /// using `$REPO` is refused.
    None,
}

/// One doc in the resolution chain (§5). Cheap to clone (just borrows).
#[derive(Clone, Copy, Debug)]
pub struct GrantDoc<'a> {
    /// A short label used in origins and error messages (e.g. `005-picker.md`,
    /// `CLAUDE.md`, `tasks/047-a-task.md`). The caller picks a convention; the
    /// resolver does not read it.
    pub label: &'a str,
    /// Raw doc content. The resolver re-reads it with [`item_meta::fields`] so
    /// a fenced example line is skipped the same way it is for `> Model:`.
    pub content: &'a str,
}

/// The small trait behind the `$WORKTREE`-must-be-of-`$REPO` check (§4), so
/// unit tests don't need real git repos. The spec: `git rev-parse --git-common-dir`
/// must match on both paths.
pub trait GitProbe {
    /// `true` when `worktree` and `repo` share one `git-common-dir`, i.e. the
    /// worktree is a worktree of the repo.
    fn same_common_dir(&self, worktree: &Path, repo: &Path) -> bool;
}

/// Inputs to [`resolve`] (§5).
#[derive(Debug)]
pub struct ResolveInputs<'a> {
    /// Milestone / sub-milestone chain, outer → inner (the top-level milestone
    /// first, the innermost sub-milestone last). For a task, this is a
    /// one-doc slice holding the task doc. For a milestone with no sub-chain,
    /// one doc with the milestone's `CLAUDE.md`.
    pub milestone_chain: &'a [GrantDoc<'a>],
    /// The active slice doc, if any. `None` for a task, a milestone's
    /// close-out, or a resolution before any slice is active.
    pub slice: Option<GrantDoc<'a>>,
    /// The item's project repo (§4).
    pub project_repo: ProjectRepo<'a>,
    /// `$HOME` for `~` expansion and the ceiling (§6).
    pub home: &'a Path,
    /// Extra ceiling entries from `config/growlight.toml`'s `grant_ceiling_extra`
    /// (§6). Add-only; nothing can remove a built-in entry.
    pub extra_ceiling: &'a [PathBuf],
    /// Which backend runs this spawn (§9: a remote `$REPO` refuses an opencode
    /// spawn before any lines resolve).
    pub backend: Backend,
    /// keeperd's state root — a resolver input per the ceiling-is-not-config
    /// rule (§6: "keeperd's state root ... come in as resolver inputs; don't
    /// read config from inside this module"). `None` leaves it out of the
    /// ceiling.
    pub keeperd_state_root: Option<&'a Path>,
    /// keeperd's vault key material path, same rule.
    pub keeperd_vault_root: Option<&'a Path>,
    /// softfig's runtime root (`$XDG_CONFIG_HOME/softfig`), floor-managed per
    /// §6. `None` leaves it out.
    pub softfig_runtime_root: Option<&'a Path>,
    /// The garden mount path — the one soft-fig garden FUSE root. Grants may
    /// not touch it (§6: house rule, garden writes go through softfig-mcp).
    pub garden_mount: Option<&'a Path>,
}

/// Resolve the grant chain. Returns the ordered list of grants (§5) or the
/// first refusal (§8).
///
/// The caller surfaces a successful result (`grants.md`, `growlight status`,
/// the opencode floor builder). An error parks the spawn once and does not
/// re-roll (§8).
pub fn resolve(inputs: &ResolveInputs<'_>, probe: &dyn GitProbe) -> Result<Vec<Grant>, GrantError> {
    // §9 pre-check: a remote repo refuses an opencode spawn before any lines
    // resolve. A claude member proceeds; its grants are advisory anyway (§10).
    if let ProjectRepo::Remote(repo) = inputs.project_repo
        && inputs.backend == Backend::Opencode
    {
        return Err(GrantError::RemoteRepoOnOpencode {
            repo: repo.to_string(),
        });
    }

    // Resolve `$REPO` to a path, remembering remote-ness so a `$REPO`-using
    // line on a claude member can still fail-closed per §5.
    let repo_path: Option<PathBuf> = match inputs.project_repo {
        ProjectRepo::Local(p) => Some(p.to_path_buf()),
        ProjectRepo::Remote(_) | ProjectRepo::None => None,
    };
    let repo_absence_reason = match inputs.project_repo {
        ProjectRepo::Local(_) => None,
        ProjectRepo::Remote(r) => Some(format!("project is remote (`{r}`)")),
        ProjectRepo::None => Some(
            "the item's queue has no registry row (legacy default queue) or project `repo` cell"
                .into(),
        ),
    };

    // Resolve `$WORKTREE` from the milestone/task chain. §4: the header lives
    // on milestones and tasks, not slices. Several milestone-chain docs may
    // declare one; the innermost declaration wins (same shape as `> Model:`).
    //
    // A slice carrying one is a parse error (§4). Check that first so a
    // mistake there is reported with a precise line.
    if let Some(slice) = inputs.slice.as_ref()
        && let Some((lineno, _)) = item_meta::fields(slice.content, item_meta::WORKTREE)
            .with_lineno()
            .next()
    {
        return Err(GrantError::WorktreeOnSlice {
            origin: Origin {
                doc: slice.label.to_string(),
                line: lineno,
                tier: Tier::Slice,
            },
        });
    }

    // Innermost-wins: walk the chain from inner → outer and take the first
    // non-empty value. `fields` yields unfenced lines only, so a fenced example
    // on a milestone doc does not get picked up.
    let worktree_declaration = inputs
        .milestone_chain
        .iter()
        .rev()
        .find_map(|doc| {
            item_meta::fields(doc.content, item_meta::WORKTREE)
                .with_lineno()
                .next()
                .map(|(lineno, value)| (doc, lineno, value))
        });

    let worktree_path: Option<PathBuf> = if let Some((doc, lineno, raw)) = worktree_declaration {
        let origin = Origin {
            doc: doc.label.to_string(),
            line: lineno,
            tier: Tier::MilestoneOrTask,
        };
        // The `> Worktree:` value is a path that may itself use `$REPO` or
        // `~`. Expand it with a synthetic "entry 0" context so an error cites
        // the Worktree line, not a Grants line.
        let expanded = expand_vars(
            raw,
            &VarContext {
                origin: &origin,
                entry_index: 0,
                home: inputs.home,
                repo_path: repo_path.as_deref(),
                repo_absence_reason: repo_absence_reason.as_deref(),
                worktree_path: None,
            },
        )?;
        let expanded = check_illegal_chars(&expanded, &origin, 0)?;
        let path = PathBuf::from(expanded);
        if !path.is_absolute() {
            return Err(GrantError::RelativePath {
                origin,
                entry_index: 0,
                path: path.to_string_lossy().into_owned(),
            });
        }
        let canonical = canonicalize_deepest(&path);
        // §4 validation at spawn: either the path exists AND is a git worktree
        // of $REPO, or it does not exist AND its parent does.
        if canonical.exists() {
            if let Some(repo) = repo_path.as_deref()
                && !probe.same_common_dir(&canonical, repo)
            {
                return Err(GrantError::WorktreeNotOfRepo {
                    worktree: canonical.to_string_lossy().into_owned(),
                    repo: repo.to_string_lossy().into_owned(),
                });
            }
            // No `$REPO` to check against: the worktree stands on its own.
        } else {
            let parent = canonical.parent().unwrap_or_else(|| Path::new("/"));
            if !parent.exists() {
                return Err(GrantError::WorktreeParentMissing {
                    worktree: canonical.to_string_lossy().into_owned(),
                    parent: parent.to_string_lossy().into_owned(),
                });
            }
        }
        Some(canonical)
    } else {
        None
    };

    // Build the ceiling list (built-ins + extras, §6). All paths resolved to
    // their canonical absolute form before comparison, so a symlink in a grant
    // path can't aim past one.
    let ceiling = build_ceiling(inputs);

    // Resolve lines in order. Each tier appends to one working list; last match
    // on a canonical path wins, slice widenings are flagged against steps 1/2.
    let mut resolved: Vec<Grant> = Vec::new();

    // Step 1: project default (§5). The resolved path is a GRANT, so it must
    // pass the grantable-root check and the ceiling. A project whose repo is
    // not a grantable root fails closed here — the resolver never silently
    // demotes a declared project to "floor only".
    if let Some(wt) = worktree_path.as_deref() {
        let origin = Origin {
            doc: worktree_declaration
                .map(|(d, _, _)| d.label.to_string())
                .unwrap_or_default(),
            line: worktree_declaration.map(|(_, l, _)| l).unwrap_or(0),
            tier: Tier::ProjectDefault,
        };
        if check_grantable_root(wt, inputs.home).is_err() {
            return Err(GrantError::UngrantableRoot {
                origin,
                entry_index: 0,
                path: wt.to_string_lossy().into_owned(),
            });
        }
        if let Some(hit) = ceiling_hit(wt, &ceiling) {
            return Err(hit.into_error(origin, 0, wt));
        }
        upsert_grant(
            &mut resolved,
            Grant {
                mode: Mode::Rw,
                path: wt.to_path_buf(),
                origin,
                widened: false,
            },
        );
    } else if let Some(repo) = repo_path.as_deref() {
        let canonical = canonicalize_deepest(repo);
        let origin = Origin {
            doc: String::new(),
            line: 0,
            tier: Tier::ProjectDefault,
        };
        if check_grantable_root(&canonical, inputs.home).is_err() {
            return Err(GrantError::UngrantableRoot {
                origin,
                entry_index: 0,
                path: canonical.to_string_lossy().into_owned(),
            });
        }
        if let Some(hit) = ceiling_hit(&canonical, &ceiling) {
            return Err(hit.into_error(origin, 0, &canonical));
        }
        upsert_grant(
            &mut resolved,
            Grant {
                mode: Mode::Rw,
                path: canonical,
                origin,
                widened: false,
            },
        );
    }

    // Snapshot the project default + any later milestone/task entries that are
    // STRICTLY at tier 1/2 before resolving slice lines, so the widening check
    // never compares a slice entry against another slice entry.
    let step12_mark = {
        // After step 1 we snapshot after step 2 is appended too.
        0usize
    };

    // Step 2: milestone/task lines, in doc order outer → inner.
    for doc in inputs.milestone_chain {
        process_doc(
            doc,
            Tier::MilestoneOrTask,
            inputs,
            repo_path.as_deref(),
            repo_absence_reason.as_deref(),
            worktree_path.as_deref(),
            &ceiling,
            &mut resolved,
        )?;
    }

    // Snapshot step-1/2 state: canonical paths and their effective (last) mode
    // in the resolved list before slice lines land, for widening (§5).
    let step12_snapshot: Vec<(PathBuf, Mode)> = {
        let _ = step12_mark;
        effective_modes(&resolved)
    };

    // Step 3: slice lines, in doc order.
    if let Some(slice) = inputs.slice.as_ref() {
        process_doc(
            slice,
            Tier::Slice,
            inputs,
            repo_path.as_deref(),
            repo_absence_reason.as_deref(),
            worktree_path.as_deref(),
            &ceiling,
            &mut resolved,
        )?;
    }

    // Mark widened on slice `rw`/`ro` entries whose access steps 1–2 did not
    // already cover (§3, §5). "Already cover" = a step-1/2 entry whose path is
    // this one OR an ancestor of it, with an access level at or above this one.
    for grant in resolved.iter_mut() {
        if grant.origin.tier == Tier::Slice && matches!(grant.mode, Mode::Rw | Mode::Ro) {
            let covered = step12_snapshot.iter().any(|(path, mode)| {
                path_covers(path, &grant.path) && mode.access_level() >= grant.mode.access_level()
            });
            grant.widened = !covered;
        }
    }

    // Append the implicit `deny <checkout>/.git` after each `rw` over a git
    // checkout. "Git checkout" means `<path>/.git` exists as a file (worktree
    // marker) or a directory (bare and worktree repos both have it); we do not
    // require the path to be a repo root, since a `rw` directly on the repo
    // root is the common case.
    let mut git_guards: Vec<Grant> = Vec::new();
    let mut seen_guards: HashSet<PathBuf> = HashSet::new();
    for grant in resolved.iter() {
        if grant.mode == Mode::Rw {
            let git_dir = grant.path.join(".git");
            if git_dir.exists() && seen_guards.insert(git_dir.clone()) {
                git_guards.push(Grant {
                    mode: Mode::Deny,
                    path: git_dir,
                    origin: Origin {
                        doc: grant.origin.doc.clone(),
                        line: grant.origin.line,
                        tier: Tier::GitGuard,
                    },
                    widened: false,
                });
            }
        }
    }
    resolved.extend(git_guards);

    // Trailing ceiling `deny`s as defense in depth (§6: "its entries are also
    // emitted as trailing `deny` rules").
    for entry in &ceiling {
        resolved.push(Grant {
            mode: Mode::Deny,
            path: entry.clone(),
            origin: Origin {
                doc: String::new(),
                line: 0,
                tier: Tier::CeilingDeny,
            },
            widened: false,
        });
    }

    Ok(resolved)
}

// --- Internal helpers ------------------------------------------------------

/// A placeholder for the shared variable-expansion context — all the inputs
/// `expand_vars` and the illegal-char check need, so entry-level helpers can
/// take one argument. Internal.
struct VarContext<'a> {
    origin: &'a Origin,
    entry_index: usize,
    home: &'a Path,
    repo_path: Option<&'a Path>,
    repo_absence_reason: Option<&'a str>,
    worktree_path: Option<&'a Path>,
}

/// Walk one doc's `> Grants:` lines in order, parse each entry, expand +
/// canonicalize, check the ceiling, and append to `resolved`. Grants on the
/// same canonical path overwrite earlier ones (last match wins).
#[allow(clippy::too_many_arguments)]
fn process_doc(
    doc: &GrantDoc<'_>,
    tier: Tier,
    inputs: &ResolveInputs<'_>,
    repo_path: Option<&Path>,
    repo_absence_reason: Option<&str>,
    worktree_path: Option<&Path>,
    ceiling: &[PathBuf],
    resolved: &mut Vec<Grant>,
) -> Result<(), GrantError> {
    for (lineno, raw) in item_meta::fields(doc.content, item_meta::GRANTS).with_lineno() {
        if raw.is_empty() {
            // A `> Grants:` with no value is a doc-author mistake; refuse so
            // it does not silently resolve to nothing.
            return Err(GrantError::Parse {
                origin: Origin {
                    doc: doc.label.to_string(),
                    line: lineno,
                    tier,
                },
                entry_index: 0,
                reason: "line has no entries".into(),
            });
        }
        let origin = Origin {
            doc: doc.label.to_string(),
            line: lineno,
            tier,
        };
        for (entry_index, entry) in raw.split(',').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                return Err(GrantError::Parse {
                    origin: origin.clone(),
                    entry_index: entry_index + 1,
                    reason: "empty entry (a doubled or trailing comma)".into(),
                });
            }
            let (mode, path_text) = parse_mode_and_path(entry).map_err(|reason| {
                GrantError::Parse {
                    origin: origin.clone(),
                    entry_index: entry_index + 1,
                    reason,
                }
            })?;
            let expanded = expand_vars(
                path_text,
                &VarContext {
                    origin: &origin,
                    entry_index: entry_index + 1,
                    home: inputs.home,
                    repo_path,
                    repo_absence_reason,
                    worktree_path,
                },
            )?;
            let expanded = check_illegal_chars(&expanded, &origin, entry_index + 1)?;
            let as_path = PathBuf::from(expanded);
            if !as_path.is_absolute() {
                return Err(GrantError::RelativePath {
                    origin: origin.clone(),
                    entry_index: entry_index + 1,
                    path: as_path.to_string_lossy().into_owned(),
                });
            }
            let canonical = canonicalize_deepest(&as_path);
            if check_grantable_root(&canonical, inputs.home).is_err() {
                return Err(GrantError::UngrantableRoot {
                    origin: origin.clone(),
                    entry_index: entry_index + 1,
                    path: canonical.to_string_lossy().into_owned(),
                });
            }
            if let Some(hit) = ceiling_hit(&canonical, ceiling) {
                return Err(hit.into_error(origin.clone(), entry_index + 1, &canonical));
            }
            upsert_grant(
                resolved,
                Grant {
                    mode,
                    path: canonical,
                    origin: origin.clone(),
                    widened: false,
                },
            );
        }
    }
    Ok(())
}

/// Parse one `<mode> <path>` entry (§3). The mode token is `rw` | `ro` | `deny`,
/// case-insensitive; the path is the rest.
fn parse_mode_and_path(entry: &str) -> Result<(Mode, &str), String> {
    let (mode_tok, rest) = entry
        .split_once(char::is_whitespace)
        .ok_or_else(|| format!("entry `{entry}` has no space between mode and path"))?;
    let mode = match mode_tok.to_ascii_lowercase().as_str() {
        "rw" => Mode::Rw,
        "ro" => Mode::Ro,
        "deny" => Mode::Deny,
        other => return Err(format!("unknown mode `{other}` (expected rw | ro | deny)")),
    };
    let path = rest.trim();
    if path.is_empty() {
        return Err("missing path after mode".into());
    }
    Ok((mode, path))
}

/// Expand `~`, `$REPO`, and `$WORKTREE` in a path string. `~user` is NOT
/// expanded (§4); it fails the "absolute path" check later.
fn expand_vars(path: &str, ctx: &VarContext<'_>) -> Result<String, GrantError> {
    // §4 allowed variables: $REPO, $WORKTREE, and ~. Any other `$NAME` is
    // unknown-variable.
    let mut out = String::with_capacity(path.len());

    // Handle a leading `~/` or `~` by itself (not `~user`).
    let (prefix_consumed, mut remainder) = if path == "~" {
        (true, "")
    } else if let Some(rest) = path.strip_prefix("~/") {
        out.push_str(&ctx.home.to_string_lossy());
        out.push('/');
        (true, rest)
    } else {
        (false, path)
    };
    if prefix_consumed && remainder.is_empty() && out.is_empty() {
        out.push_str(&ctx.home.to_string_lossy());
    }

    while let Some(dollar) = remainder.find('$') {
        out.push_str(&remainder[..dollar]);
        let after = &remainder[dollar + 1..];
        let name_end = after
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(after.len());
        if name_end == 0 {
            return Err(GrantError::UnknownVariable {
                origin: ctx.origin.clone(),
                entry_index: ctx.entry_index,
                name: String::new(),
                path: path.to_string(),
            });
        }
        let name = &after[..name_end];
        let value: &str = match name {
            "REPO" => match ctx.repo_path {
                Some(p) => return_cow(p),
                None => {
                    return Err(GrantError::UnresolvableVariable {
                        origin: ctx.origin.clone(),
                        entry_index: ctx.entry_index,
                        name: name.to_string(),
                        reason: ctx
                            .repo_absence_reason
                            .map(str::to_string)
                            .unwrap_or_else(|| "no local repo for this project".to_string()),
                        path: path.to_string(),
                    });
                }
            },
            "WORKTREE" => match ctx.worktree_path {
                Some(p) => return_cow(p),
                None => {
                    return Err(GrantError::UnresolvableVariable {
                        origin: ctx.origin.clone(),
                        entry_index: ctx.entry_index,
                        name: name.to_string(),
                        reason: "the item declares no `> Worktree:`".to_string(),
                        path: path.to_string(),
                    });
                }
            },
            _ => {
                return Err(GrantError::UnknownVariable {
                    origin: ctx.origin.clone(),
                    entry_index: ctx.entry_index,
                    name: name.to_string(),
                    path: path.to_string(),
                });
            }
        };
        out.push_str(value);
        remainder = &after[name_end..];
    }
    out.push_str(remainder);
    Ok(out)
}

/// A tiny borrow helper to let `expand_vars` return a `&str` from a `&Path`
/// without lifetime acrobatics (the string lives for the match arm only).
fn return_cow(path: &Path) -> &str {
    // `Path::to_str` returns `Option<&str>` with the SAME lifetime as `&Path`,
    // which is exactly what we want. On non-UTF-8 paths this returns `""`,
    // which is harmless: the path then fails the absolute-path check later
    // with a precise error citing the entry.
    path.to_str().unwrap_or_default()
}

/// Refuse paths containing `*`, `?`, or any control character (§3). Returns
/// the string unchanged on success.
fn check_illegal_chars(
    path: &str,
    origin: &Origin,
    entry_index: usize,
) -> Result<String, GrantError> {
    for ch in path.chars() {
        if ch == '*' || ch == '?' || ch.is_control() {
            return Err(GrantError::IllegalChar {
                origin: origin.clone(),
                entry_index,
                path: path.to_string(),
                bad: ch,
            });
        }
    }
    Ok(path.to_string())
}

/// Canonicalize `path` by resolving symlinks on its deepest existing ancestor
/// and re-appending the trailing non-existent components (§5). On any I/O
/// error the input is returned verbatim; the ceiling check still runs on the
/// result.
fn canonicalize_deepest(path: &Path) -> PathBuf {
    // Try the whole path first (the fast path for an existing dir).
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    // Peel one trailing component at a time until a prefix canonicalizes;
    // re-append the peeled components as plain segments.
    let mut peeled: Vec<std::ffi::OsString> = Vec::new();
    let mut head = path.to_path_buf();
    loop {
        let Some(name) = head.file_name().map(|n| n.to_os_string()) else {
            return path.to_path_buf();
        };
        peeled.push(name);
        if !head.pop() {
            return path.to_path_buf();
        }
        if let Ok(canonical) = std::fs::canonicalize(&head) {
            let mut result = canonical;
            for seg in peeled.into_iter().rev() {
                result.push(seg);
            }
            return result;
        }
        if head.as_os_str().is_empty() {
            return path.to_path_buf();
        }
    }
}

/// Grantable-root check (§6): a path must be strictly under `$HOME` OR
/// strictly under `/tmp/<name>/` (not `/`, not bare `$HOME`, not bare `/tmp`,
/// not a sibling of either). Runs before [`ceiling_hit`] so `$HOME`-root-only
/// paths like `~/dotfiles` are not misread as ceiling hits.
///
/// Bare `$HOME` is refused up front: in tests `$HOME` happens to sit under
/// `/tmp/<tmpid>/`, so the `/tmp/<name>/` branch would otherwise accept it.
fn check_grantable_root(path: &Path, home: &Path) -> Result<(), ()> {
    // Bare `$HOME` and `/` are never grantable roots.
    if path == home || path == Path::new("/") {
        return Err(());
    }
    // Strictly under $HOME.
    if path.starts_with(home) {
        return Ok(());
    }
    // Strictly under `/tmp/<name>/`: strip `/tmp`, require at least one more
    // Normal component (so `/tmp` alone is refused; `/tmp/foo` is OK).
    if let Ok(rest) = path.strip_prefix("/tmp") {
        let mut comps = rest.components();
        if let Some(std::path::Component::Normal(_)) = comps.next() {
            return Ok(());
        }
    }
    Err(())
}

/// Ceiling check (§6): does `path` equal, sit inside, or ancestor any entry?
fn ceiling_hit<'a>(path: &Path, ceiling: &'a [PathBuf]) -> Option<CeilingHitKind<'a>> {
    for entry in ceiling {
        if path == entry.as_path() {
            return Some(CeilingHitKind {
                entry,
                relation: CeilingRelation::Equal,
            });
        }
        if path_contains(entry, path) {
            return Some(CeilingHitKind {
                entry,
                relation: CeilingRelation::Inside,
            });
        }
        if path_contains(path, entry) {
            return Some(CeilingHitKind {
                entry,
                relation: CeilingRelation::AncestorOf,
            });
        }
    }
    None
}

/// Internal helper to carry a ceiling hit back to [`GrantError::CeilingHit`]
/// with the right path and entry text.
struct CeilingHitKind<'a> {
    entry: &'a Path,
    relation: CeilingRelation,
}

impl CeilingHitKind<'_> {
    fn into_error(self, origin: Origin, entry_index: usize, path: &Path) -> GrantError {
        GrantError::CeilingHit {
            origin,
            entry_index,
            path: path.to_string_lossy().into_owned(),
            entry: self.entry.to_string_lossy().into_owned(),
            relation: self.relation,
        }
    }
}

/// `true` when `outer` is a strict ancestor of `inner` (not equal). Equality
/// is checked separately in [`ceiling_hit`].
fn path_contains(outer: &Path, inner: &Path) -> bool {
    if outer == inner {
        return false;
    }
    inner.starts_with(outer)
}

/// `true` when `outer` equals `inner` OR `outer` is a strict ancestor of
/// `inner` — i.e. a grant on `outer` covers `inner`. The widening check uses
/// this (a step-1/2 entry on `/a` covers `/a` and every `/a/sub`).
fn path_covers(outer: &Path, inner: &Path) -> bool {
    outer == inner || inner.starts_with(outer)
}

/// Insert `grant` or overwrite the existing grant on the same canonical path
/// (last match wins, §5). Order is preserved: an overwrite is replaced
/// in-place; a fresh path is appended.
fn upsert_grant(resolved: &mut Vec<Grant>, grant: Grant) {
    if let Some(existing) = resolved.iter_mut().find(|g| g.path == grant.path) {
        *existing = grant;
    } else {
        resolved.push(grant);
    }
}

/// The effective (last) mode on each path in `resolved`, for widening checks.
fn effective_modes(resolved: &[Grant]) -> Vec<(PathBuf, Mode)> {
    resolved
        .iter()
        .map(|g| (g.path.clone(), g.mode))
        .collect()
}

/// Build the ceiling list (§6). Order: built-ins first, then
/// `grant_ceiling_extra`. Entries are canonicalized the same way grant paths
/// are, so a symlink in a ceiling root does not weaken the check.
///
/// `$HOME` and `/` are deliberately NOT in this list — they are refused by
/// [`check_grantable_root`], which runs first. Putting `$HOME` here would
/// refuse every legitimate `~/<sub>` grant as `Inside` of `$HOME`.
fn build_ceiling(inputs: &ResolveInputs<'_>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    // `/tmp/opencode`: scratch shared with other tools.
    out.push(PathBuf::from("/tmp/opencode"));
    // Credentials & key material under $HOME.
    for sub in [".ssh", ".gnupg", ".password-store", ".claude"] {
        out.push(inputs.home.join(sub));
    }
    // opencode's own state.
    out.push(inputs.home.join(".config/opencode"));
    out.push(inputs.home.join(".local/share/opencode"));
    // Persistence (would run as the human).
    out.push(inputs.home.join(".config/systemd"));
    out.push(inputs.home.join(".local/bin"));
    // Caller-supplied floor roots and the garden mount.
    if let Some(p) = inputs.softfig_runtime_root {
        out.push(p.to_path_buf());
    }
    if let Some(p) = inputs.keeperd_state_root {
        out.push(p.to_path_buf());
    }
    if let Some(p) = inputs.keeperd_vault_root {
        out.push(p.to_path_buf());
    }
    if let Some(p) = inputs.garden_mount {
        out.push(p.to_path_buf());
    }
    out.extend(inputs.extra_ceiling.iter().cloned());
    // Canonicalize what exists; leave non-existent entries as-is (so a
    // not-yet-created vault root still participates in the check by path).
    out.into_iter().map(|p| canonicalize_deepest(&p)).collect()
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.doc.is_empty() {
            write!(f, "<{}>", self.tier.label())
        } else if self.line == 0 {
            write!(f, "{} ({})", self.doc, self.tier.label())
        } else {
            write!(f, "{}:{} ({})", self.doc, self.line, self.tier.label())
        }
    }
}

#[cfg(test)]
mod tests {
    include!("grants_tests.rs");
}
