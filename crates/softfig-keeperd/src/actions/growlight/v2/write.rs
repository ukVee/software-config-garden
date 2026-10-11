//! The **only** writer path for the v2 TOML files and their derived views.
//!
//! A verb's write half is: load ([`super::state`]), mutate the in-memory
//! models, validate (its own refusal vocabulary), then call [`apply`] once
//! with every file it changed and every view that must re-render. `apply`
//! does the whole-file CAS checks, stages the writes through the worktree,
//! upserts/removes the managed regions, and commits **exactly once** with an
//! intent naming the verb — all files a verb touches land in one commit, no
//! partial writes. Any other writes the verb staged earlier (entry docs, a
//! backlink refresh) ride that same commit; the verb must never commit itself.
//!
//! The CAS token is the load's [`LoadedFile::version`]: `Some(hash)` means
//! the file must still read those bytes; `None` means this is the first
//! creation and the file must not exist. Either drift refuses the write with
//! `Conflict` before anything is staged, so a stale or hand-edited file is
//! never clobbered. First creation writes `schema = 1` + the mutated rows —
//! the model constructors stamp the schema and the serializer refuses to
//! emit anything else.

use softfig_ipc::ErrorKind;
use softfig_store::Hash;
use softfig_vcs::Intent;

use crate::actions::growlight::paths;
use crate::actions::{managed, sections, WorkTree};
use crate::daemon::{Daemon, DaemonInner};

/// One v2 file to write: the path, the CAS token from the load, and the
/// serialized bytes.
pub struct FileWrite {
    pub rel: String,
    /// [`LoadedFile::version`](super::state::LoadedFile::version) from the
    /// verb's load: `Some(hash)` = the file must still read those bytes;
    /// `None` = first creation, the file must not exist.
    pub expected: Option<String>,
    pub bytes: Vec<u8>,
}

/// One derived view to re-render (§3.4): the host doc, the managed-region
/// tag, and the rendered body — or `None` to remove the region, which the
/// verb passes when its load found the TOML file absent (no file, no view).
pub struct ViewWrite {
    pub host: String,
    pub tag: &'static str,
    pub body: Option<String>,
}

/// Stage every [`FileWrite`] (CAS-checked) and [`ViewWrite`] through the
/// worktree, then commit once with `intent_name` naming the verb. Returns the
/// commit hash (the untouched tip when nothing changed on disk — same-tree
/// writes mint no commit).
///
/// All-or-nothing: every check runs before the first write, so a refusal
/// (a stale CAS token, a file that appeared, an unreadable view host) stages
/// nothing — no partial writes, and the single commit only ever fires with
/// the whole verb's state ready.
pub fn apply(
    daemon: &Daemon,
    inner: &mut DaemonInner,
    intent_name: &str,
    payload: serde_json::Value,
    files: &[FileWrite],
    views: &[ViewWrite],
) -> Result<Hash, (ErrorKind, String)> {
    crate::handlers::require_unlocked(inner)?;
    {
        let wt = WorkTree::new(daemon, inner);
        // Pass 1 — refuse everything that could fail, before anything lands.
        for f in files {
            wt.check_write(&f.rel)?;
            match &f.expected {
                Some(_) => crate::handlers::cas_check_whole_file(&wt, &f.rel, &f.expected)?,
                None => {
                    // First creation: the verb loaded no file, so the file must
                    // still be absent.
                    if wt.exists(&f.rel) {
                        return Err((
                            ErrorKind::Conflict,
                            format!(
                                "{}: expected absent (first creation) but the file now exists",
                                f.rel
                            ),
                        ));
                    }
                }
            }
        }
        let hosts: Result<Vec<Option<String>>, (ErrorKind, String)> = views
            .iter()
            .map(|v| read_view_host(&wt, inner, &v.host, v.body.is_some()))
            .collect();
        let hosts = hosts?;
        // Pass 2 — stage every write.
        for f in files {
            wt.write(&f.rel, &f.bytes)?;
        }
        for (v, host) in views.iter().zip(hosts) {
            let Some(content) = host else {
                continue; // removing a region from a doc that doesn't exist: done
            };
            let new = match &v.body {
                Some(body) => managed::upsert(&content, v.tag, body),
                None => managed::remove(&content, v.tag),
            };
            if new != content {
                wt.check_write(&v.host)?;
                wt.write(&v.host, new.as_bytes())?;
            }
        }
    }
    let intent = Intent::new(intent_name, payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    crate::actions::commit_now(inner, intent)
}

/// Read a view's host doc through the same guard the legacy verbs use. A
/// missing host is created from the backlog stub only for the queue view
/// (mirroring `add_backlog_item` self-materializing its routing doc); any
/// other missing host is the verb's bug — refuse, never fabricate a doc.
fn read_view_host(
    wt: &WorkTree,
    inner: &DaemonInner,
    host: &str,
    upserting: bool,
) -> Result<Option<String>, (ErrorKind, String)> {
    if let Some(content) = sections::read_if_unprotected(wt, inner, host) {
        return Ok(Some(content));
    }
    if wt.exists(host) {
        return Err((
            ErrorKind::VaultProtected,
            format!("{host}: unreadable or vault-protected"),
        ));
    }
    if !upserting {
        return Ok(None);
    }
    if host == paths::backlog_claude() {
        return Ok(Some(paths::backlog_claude_stub()));
    }
    Err((
        ErrorKind::NotFound,
        format!("{host}: view host missing — the verb must create the doc first"),
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::actions::growlight::v2::{state, views};
    use crate::actions::WorkTree;
    use crate::config::KeeperConfig;
    use crate::handlers;
    use softfig_ipc::queue_v2::{
        Entry, EntryKind, EntryStatus, Lane, Project, QueueArchiveToml, QueueToml, SlicesToml,
        SliceItem, SliceKind, SliceStatus, QUEUE_FILE,
    };
    use softfig_vault::{params::VaultParams, Vault};
    use softfig_vcs::TIP_REF;

    const PASS: &[u8] = b"pw-test-12345";

    /// An unlocked Disk-mode daemon over a fresh tempdir garden: no FUSE, so
    /// the worktree reads/writes go to disk and `commit_now` walks the
    /// working tree. Built through the real unlock path, like the ceremony
    /// tests. Shared by the slice-004 verb tests (`queue_verbs`).
    pub(crate) fn unlocked(garden: &std::path::Path) -> Daemon {
        let mut params = VaultParams::default();
        params.argon2.m_cost = 8;
        params.argon2.t_cost = 1;
        params.argon2.p_cost = 1;
        let (_v, session, _r) = Vault::init_with_params(garden, PASS, params).unwrap();
        softfig_vcs::Repo::init(garden, &session).unwrap();
        drop(session);
        let daemon = Daemon::new(
            KeeperConfig::new(garden)
                .without_watcher()
                .without_net()
                .without_fuse(),
        );
        let reply = handlers::unlock(
            &daemon,
            serde_json::json!({ "passphrase": String::from_utf8_lossy(PASS) }),
        );
        assert!(reply.is_ok(), "unlock: {reply:?}");
        daemon
    }

    fn project() -> Project {
        Project {
            name: "softfig".to_string(),
            repo: "~/p".to_string(),
            main: "main".to_string(),
        }
    }

    fn entry(id: &str, lane: Lane) -> Entry {
        Entry {
            id: id.to_string(),
            kind: EntryKind::Milestone,
            title: format!("{id} title"),
            project: "softfig".to_string(),
            lane,
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

    /// Serialize + write a fresh queue via `apply` and hand back the model +
    /// its CAS token for later writes.
    fn create_queue(
        daemon: &Daemon,
        queue: &QueueToml,
        archive: Option<&QueueArchiveToml>,
    ) {
        let mut inner = daemon.inner.lock().unwrap();
        let mut files = vec![FileWrite {
            rel: state::QUEUE_FILE.to_string(),
            expected: None,
            bytes: queue.to_toml().expect("serialize").into_bytes(),
        }];
        if let Some(a) = archive {
            files.push(FileWrite {
                rel: state::QUEUE_ARCHIVE_FILE.to_string(),
                expected: None,
                bytes: a.to_toml().expect("serialize").into_bytes(),
            });
        }
        apply(
            daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({ "test": true }),
            &files,
            &[ViewWrite {
                host: views::queue_view_host(),
                tag: views::QUEUE_V2_TAG,
                body: Some(views::queue_view(queue)),
            }],
        )
        .expect("apply");
    }

    fn commit_count(daemon: &Daemon) -> usize {
        let inner = daemon.inner.lock().unwrap();
        let repo = inner.repo.as_ref().unwrap();
        let tip = repo.tip_of(TIP_REF).unwrap().expect("genesis tip");
        softfig_vcs::log::collect(repo.db(), tip).unwrap().len()
    }

    /// Write a file straight into the garden behind the worktree — the
    /// hand-edit shape a FUSE mount would stage (creating parents like a
    /// real editor would).
    fn hand_write(garden: &std::path::Path, rel: &str, content: &str) {
        let abs = garden.join(rel);
        std::fs::create_dir_all(abs.parent().expect("nested path")).unwrap();
        std::fs::write(abs, content).unwrap();
    }

    #[test]
    fn create_then_read_back_round_trips_and_renders_the_view() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        create_queue(&daemon, &q, None);

        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let loaded = state::load_queue_state(&wt, &inner)
                .expect("load")
                .expect("queue exists");
            assert_eq!(loaded.queue.model, q, "read-back is exact");
            assert!(loaded.queue.version.is_some());
            assert!(loaded.archive.version.is_none(), "archive was never created");
            assert!(loaded.archive.model.entries.is_empty());

            // The view rendered into the backlog doc, inside the managed region.
            let backlog = wt
                .read_to_string(&views::queue_view_host())
                .expect("backlog doc exists");
            let body = managed::region_body(&backlog, views::QUEUE_V2_TAG)
                .expect("queue-v2 region present");
            assert!(body.contains("a"), "{body}");
            assert!(body.contains("### Urgent"));
            assert!(body.contains("### Normal"));
        }

        // And the TOML is a real file on disk in the garden.
        assert!(garden.path().join(QUEUE_FILE).is_file());
    }

    #[test]
    fn load_refuses_invalid_toml_schema_2_and_invariant_violations() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());

        // A garden with no v2 files loads as None (not an error).
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            assert!(state::load_queue_state(&wt, &inner).unwrap().is_none());
        }

        let rel = QUEUE_FILE;
        // 1. Garbage TOML.
        hand_write(garden.path(), rel, "not toml {{{");
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            assert!(matches!(
                state::load_queue_state(&wt, &inner),
                Err(state::V2FileError::InvalidToml { .. })
            ));
        }
        // 2. A schema this build does not write.
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        let future = q.to_toml().unwrap().replace("schema = 1", "schema = 2");
        hand_write(garden.path(), rel, &future);
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            assert!(matches!(
                state::load_queue_state(&wt, &inner),
                Err(state::V2FileError::InvalidToml {
                    source: softfig_ipc::queue_v2::QueueV2Error::UnsupportedSchema { found: 2 },
                    ..
                })
            ));
        }
        // 3. Parses but violates a §3.1 invariant (duplicate id).
        let mut dup = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        dup.entries.push(entry("a", Lane::Normal));
        hand_write(garden.path(), rel, &dup.to_toml().unwrap());
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            assert!(matches!(
                state::load_queue_state(&wt, &inner),
                Err(state::V2FileError::InvalidState {
                    refusal: softfig_ipc::queue_v2::QueueRefusal::Exists { .. },
                    ..
                })
            ));
        }
    }

    #[test]
    fn a_write_mints_exactly_one_commit_and_an_identical_write_mints_none() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        let before = commit_count(&daemon);
        create_queue(&daemon, &q, None);
        assert_eq!(commit_count(&daemon), before + 1, "exactly one commit per write");

        // Re-apply identical bytes under the real CAS token: same tree, no
        // commit minted (no churn).
        let mut inner = daemon.inner.lock().unwrap();
        let version = {
            let wt = WorkTree::new(&daemon, &inner);
            state::load_queue_state(&wt, &inner)
                .unwrap()
                .unwrap()
                .queue
                .version
                .unwrap()
        };
        apply(
            &daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({}),
            &[FileWrite {
                rel: state::QUEUE_FILE.to_string(),
                expected: Some(version),
                bytes: q.to_toml().unwrap().into_bytes(),
            }],
            &[ViewWrite {
                host: views::queue_view_host(),
                tag: views::QUEUE_V2_TAG,
                body: Some(views::queue_view(&q)),
            }],
        )
        .expect("identical re-apply");
        drop(inner);
        assert_eq!(
            commit_count(&daemon),
            before + 1,
            "an identical write mints no commit (no churn)"
        );
    }

    #[test]
    fn cas_refuses_a_stale_write_and_leaves_the_file_untouched() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        create_queue(&daemon, &q, None);

        // Load, then a hand-edit lands (the FUSE-mount hand-edit shape — here
        // simulated with a plain disk write between load and apply).
        let mut inner = daemon.inner.lock().unwrap();
        let (version, mutated) = {
            let wt = WorkTree::new(&daemon, &inner);
            let loaded = state::load_queue_state(&wt, &inner).unwrap().unwrap();
            (loaded.queue.version.unwrap(), entry("stale-wins", Lane::Urgent))
        };
        hand_write(garden.path(), QUEUE_FILE, "schema = 1\n[[entry]]\n");

        let err = apply(
            &daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({}),
            &[FileWrite {
                rel: state::QUEUE_FILE.to_string(),
                expected: Some(version),
                bytes: QueueToml::new(vec![project()], vec![mutated.clone()])
                    .to_toml()
                    .unwrap()
                    .into_bytes(),
            }],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::Conflict, "{err:?}");

        // The hand-edited bytes are untouched by the refused write.
        let on_disk = std::fs::read_to_string(garden.path().join(QUEUE_FILE)).unwrap();
        assert!(on_disk.starts_with("schema = 1\n[[entry]]\n"), "{on_disk}");
    }

    #[test]
    fn cas_refuses_first_creation_when_the_file_appeared() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // The file appears between the verb's (absent) load and its apply.
        hand_write(garden.path(), QUEUE_FILE, "schema = 1\n");
        let mut inner = daemon.inner.lock().unwrap();
        let err = apply(
            &daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({}),
            &[FileWrite {
                rel: state::QUEUE_FILE.to_string(),
                expected: None,
                bytes: QueueToml::new(vec![], vec![])
                    .to_toml()
                    .unwrap()
                    .into_bytes(),
            }],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::Conflict, "{err:?}");
        // Untouched.
        let on_disk = std::fs::read_to_string(garden.path().join(QUEUE_FILE)).unwrap();
        assert_eq!(on_disk, "schema = 1\n");
    }

    #[test]
    fn one_verb_two_files_one_commit_and_both_views_render() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        // The milestone doc the slices view hosts (queue_add_entry creates it
        // in slice 004; here the harness seeds it like the verb would).
        let milestone_doc_rel = "growlight/backlog/milestones/m/CLAUDE.md";
        {
            let mut inner = daemon.inner.lock().unwrap();
            {
                let wt = WorkTree::new(&daemon, &inner);
                wt.write(milestone_doc_rel, b"# backlog: m\n\n## Mission\n\nwhy\n")
                    .unwrap();
            }
            crate::actions::commit_now(&mut inner, Intent::init("seed milestone doc")).unwrap();
        }

        let q = QueueToml::new(vec![project()], vec![entry("m", Lane::Normal)]);
        let s = SlicesToml::new(
            "m".to_string(),
            vec![SliceItem {
                kind: SliceKind::Slice,
                id: "001".to_string(),
                status: SliceStatus::Queued,
                follow_ups: Some(0),
            }],
        );
        let before = commit_count(&daemon);
        {
            let mut inner = daemon.inner.lock().unwrap();
            apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({}),
                &[
                    FileWrite {
                        rel: state::QUEUE_FILE.to_string(),
                        expected: None,
                        bytes: q.to_toml().unwrap().into_bytes(),
                    },
                    FileWrite {
                        rel: state::slices_file("m"),
                        expected: None,
                        bytes: s.to_toml().unwrap().into_bytes(),
                    },
                ],
                &[
                    ViewWrite {
                        host: views::queue_view_host(),
                        tag: views::QUEUE_V2_TAG,
                        body: Some(views::queue_view(&q)),
                    },
                    ViewWrite {
                        host: views::slices_view_host("m"),
                        tag: views::SLICES_V2_TAG,
                        body: Some(views::slices_view(&s)),
                    },
                ],
            )
            .expect("apply");
        }
        assert_eq!(commit_count(&daemon), before + 1, "both files in one commit");

        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        assert!(wt.exists(state::QUEUE_FILE));
        assert!(wt.exists(&state::slices_file("m")));
        assert!(managed::has_region(
            &wt.read_to_string(&views::queue_view_host()).unwrap(),
            views::QUEUE_V2_TAG
        ));
        assert!(managed::has_region(
            &wt.read_to_string(milestone_doc_rel).unwrap(),
            views::SLICES_V2_TAG
        ));
        assert!(state::load_slices(&wt, &inner, "m")
            .expect("load slices")
            .is_some());
    }

    #[test]
    fn a_removal_view_drops_the_region_and_a_missing_milestone_host_refuses() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        create_queue(&daemon, &q, None);

        // Remove: body None + no files — the region vanishes from the doc.
        {
            let mut inner = daemon.inner.lock().unwrap();
            apply(
                &daemon,
                &mut inner,
                "queue_v2_updated",
                serde_json::json!({}),
                &[],
                &[ViewWrite {
                    host: views::queue_view_host(),
                    tag: views::QUEUE_V2_TAG,
                    body: None,
                }],
            )
            .expect("apply removal");
        }
        {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            let backlog = wt.read_to_string(&views::queue_view_host()).unwrap();
            assert!(
                !managed::has_region(&backlog, views::QUEUE_V2_TAG),
                "region removed: {backlog}"
            );
            // The doc still exists and kept its prose.
            assert!(backlog.contains("growlight/backlog"), "{backlog}");
        }

        // A missing milestone host with an upsert is refused, not fabricated.
        let mut inner = daemon.inner.lock().unwrap();
        let err = apply(
            &daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({}),
            &[],
            &[ViewWrite {
                host: views::slices_view_host("ghost"),
                tag: views::SLICES_V2_TAG,
                body: Some("x".to_string()),
            }],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::NotFound, "{err:?}");
    }

    #[test]
    fn a_late_cas_failure_stages_nothing() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        create_queue(&daemon, &q, None);

        // Load the queue, then a hand-edit lands. Apply two files where only
        // the second CAS fails — the first file must not be written either
        // (all-or-nothing: every check runs before the first write).
        let version = {
            let inner = daemon.inner.lock().unwrap();
            let wt = WorkTree::new(&daemon, &inner);
            state::load_queue_state(&wt, &inner)
                .unwrap()
                .unwrap()
                .queue
                .version
                .unwrap()
        };
        hand_write(garden.path(), QUEUE_FILE, "schema = 1\n[[entry]]\n");
        let commits_before = commit_count(&daemon);

        let mut inner = daemon.inner.lock().unwrap();
        let err = apply(
            &daemon,
            &mut inner,
            "queue_v2_updated",
            serde_json::json!({}),
            &[
                FileWrite {
                    rel: state::slices_file("m"),
                    expected: None,
                    bytes: b"schema = 1\n".to_vec(),
                },
                FileWrite {
                    rel: state::QUEUE_FILE.to_string(),
                    expected: Some(version),
                    bytes: q.to_toml().unwrap().into_bytes(),
                },
            ],
            &[],
        )
        .unwrap_err();
        assert_eq!(err.0, ErrorKind::Conflict, "{err:?}");
        // Nothing was staged: the first file does not exist and the
        // hand-edited queue bytes stand.
        assert!(
            !garden.path().join(state::slices_file("m")).exists(),
            "the first file must not be written when a later CAS fails"
        );
        assert_eq!(
            std::fs::read_to_string(garden.path().join(QUEUE_FILE)).unwrap(),
            "schema = 1\n[[entry]]\n",
            "hand-edited bytes untouched"
        );
        drop(inner);
        assert_eq!(
            commit_count(&daemon),
            commits_before,
            "a refused apply mints no commit"
        );
    }

    #[test]
    fn queue_view_host_self_materializes_on_a_fresh_garden() {
        let garden = tempfile::tempdir().unwrap();
        let daemon = unlocked(garden.path());
        let q = QueueToml::new(vec![project()], vec![entry("a", Lane::Normal)]);
        // No backlog doc exists; apply creates the stub and renders into it.
        create_queue(&daemon, &q, None);
        let inner = daemon.inner.lock().unwrap();
        let wt = WorkTree::new(&daemon, &inner);
        let backlog = wt.read_to_string(&views::queue_view_host()).unwrap();
        assert!(managed::has_region(&backlog, views::QUEUE_V2_TAG));
        // The pre-existing legacy prose comes from the stub, untouched.
        assert!(backlog.contains("The growlight work queue."), "{backlog}");
    }
}
