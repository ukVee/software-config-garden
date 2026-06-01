//! Per-verb handlers. Each takes the shared daemon handle and the raw
//! args `Value`, returns either the success-data `Value` or an
//! (ErrorKind, message) pair.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use softfig_core::{fsck as run_fsck, log_collect, Intent, Repo};
use softfig_fuse::SealedQuery;
use softfig_ipc::verbs::{
    CommitArgs, CommitReply, DocFile, FsckReply, LogArgs, LogEntry, LogReply,
    MigrateFinalizeArgs, MigrateFinalizeReply, ProposeDocUpdateArgs,
    ProposeDocUpdateReply, ShowArgs, ShowCommit, ShowReply, ShowTreeEntry,
    StatusReply, UnlockArgs, UnlockReply, VaultListSealedReply, VaultRevealArgs,
    VaultRevealReply, VaultSealArgs, VaultSealReply, VaultUnsealArgs,
    VaultUnsealReply,
};
use softfig_ipc::ErrorKind;
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::Vault;

use crate::daemon::{Daemon, KeeperError};
use crate::layer_b::{self, LayerBHook, PriorTipGuard, SealedPaths};
use crate::server::err_to_response;
use crate::state::State;

pub type HandlerResult = std::result::Result<serde_json::Value, (ErrorKind, String)>;

const PROJECT: &str = "softfig-keeperd";

pub fn status(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    let tip_hex = match inner.repo.as_ref() {
        Some(repo) => repo.tip().ok().flatten().map(|h| h.to_string()),
        None => None,
    };
    let reply = StatusReply {
        state: inner.state.label().to_string(),
        tip: tip_hex,
        garden_root: inner.config.garden_root.display().to_string(),
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
    };
    Ok(serde_json::to_value(reply).unwrap())
}

pub fn unlock(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: UnlockArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("unlock args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    if inner.state == State::Stopping {
        return Err((ErrorKind::Internal, "daemon stopping".into()));
    }
    if inner.state == State::Unlocked {
        return Ok(serde_json::to_value(UnlockReply {
            state: State::Unlocked.label().to_string(),
        })
        .unwrap());
    }

    let garden_root = inner.config.garden_root.clone();
    let state_dir = inner.config.state_dir().to_path_buf();
    let vault = Vault::at_state_root(&state_dir);
    if !vault.is_initialized() {
        return Err((
            ErrorKind::NotFound,
            format!("no vault at {}/.softfig/vault", state_dir.display()),
        ));
    }

    let session = vault
        .unlock(args.passphrase.as_bytes())
        .map_err(|e| (ErrorKind::AuthFailed, e.to_string()))?;

    let state_root = inner.config.state_root.clone();
    let mut repo = Repo::open_with(&garden_root, state_root.as_deref())
        .map_err(|e| err_to_response(e.into()))?;

    let session_arc = Arc::new(session);

    // M2b: load (or initialize-empty) the sealed-paths matcher from
    // `<state_dir>/.softfig/vault/sealed-paths.toml`. The hook
    // double-duties as the Repo's blob encryptor (commit-time routing)
    // and the FUSE driver's SealedQuery (read-path placeholder).
    let state_dir = inner.config.state_dir().to_path_buf();
    let sealed = match SealedPaths::load(&state_dir) {
        Ok(sp) => sp,
        Err(e) => {
            eprintln!(
                "keeperd: unlock: sealed-paths.toml load failed ({e}); \
                 continuing with empty matcher"
            );
            SealedPaths::empty()
        }
    };
    let hook: Arc<LayerBHook> = Arc::new(LayerBHook::new(sealed));
    // M2c — give the hook a session handle so its read-path
    // `redact_regions` can trial-decrypt inline region bodies without
    // going through the BlobEncryptor write path.
    hook.set_session(Some(session_arc.clone()));
    repo.set_blob_encryptor(hook.clone());

    // M2a: mount the FUSE filesystem and register the tip-changed
    // callback. M1c-compat (no state_root) skips this entirely.
    let fuse_handle = if inner.config.is_fuse_mode() && inner.config.enable_fuse {
        let sink = crate::fuse_sink::AccumulatorSink::spawn(daemon.accumulator.clone());
        let sealed_q: Arc<dyn SealedQuery> = hook.clone();
        match softfig_fuse::FuseMount::mount_with(
            &garden_root,
            &state_dir,
            session_arc.clone(),
            sink,
            Some(sealed_q),
        ) {
            Ok(handle) => {
                softfig_fuse::FuseMount::install_tip_callback(&mut repo, &handle);
                Some(handle)
            }
            Err(e) => {
                return Err((
                    ErrorKind::Io,
                    format!("fuse mount at {}: {e}", garden_root.display()),
                ));
            }
        }
    } else {
        None
    };

    inner.session = Some(session_arc);
    inner.repo = Some(repo);
    inner.fuse = fuse_handle;
    inner.layer_b = hook;
    inner.last_reveal_at = None;
    inner.state = State::Unlocked;

    Ok(serde_json::to_value(UnlockReply {
        state: State::Unlocked.label().to_string(),
    })
    .unwrap())
}

pub fn commit(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: CommitArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("commit args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let intent = Intent::new(&args.intent, args.payload)
        .map_err(|e| (ErrorKind::BadArgs, e.to_string()))?;

    let inner = &mut *inner;
    let hook = inner.layer_b.clone();
    let session = inner.session.as_ref().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
    let hash = repo
        .commit_workdir(session, intent)
        .map_err(|e| err_to_response(e.into()))?;
    Ok(serde_json::to_value(CommitReply {
        hash: hash.to_string(),
    })
    .unwrap())
}

pub fn log(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: LogArgs = serde_json::from_value(args).unwrap_or(LogArgs { limit: 0 });
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let repo = inner.repo.as_ref().expect("unlocked");
    let tip = match repo.tip().map_err(|e| err_to_response(e.into()))? {
        Some(h) => h,
        None => {
            return Ok(serde_json::to_value(LogReply { commits: vec![] }).unwrap())
        }
    };

    let commits = log_collect(repo.db(), tip).map_err(|e| err_to_response(e.into()))?;
    let limit = if args.limit == 0 {
        commits.len()
    } else {
        args.limit.min(commits.len())
    };

    let entries = commits
        .iter()
        .take(limit)
        .map(|c| LogEntry {
            hash: c.hash.to_string(),
            timestamp: c.timestamp,
            intent: c.intent.clone(),
            summary: short_summary(&c.payload),
        })
        .collect();

    Ok(serde_json::to_value(LogReply { commits: entries }).unwrap())
}

pub fn show(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ShowArgs = serde_json::from_value(args).unwrap_or(ShowArgs { hash: None });
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let repo = inner.repo.as_ref().expect("unlocked");
    let target = match args.hash {
        Some(hex) => Hash::from_hex(&hex)
            .map_err(|e| (ErrorKind::BadArgs, format!("hash: {e}")))?,
        None => repo
            .tip()
            .map_err(|e| err_to_response(e.into()))?
            .ok_or_else(|| (ErrorKind::NotFound, "no commits".into()))?,
    };

    let row = repo
        .db()
        .get_commit(&target)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;
    let entries = repo
        .db()
        .get_tree(&row.root_tree)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;

    let reply = ShowReply {
        commit: ShowCommit {
            hash: row.hash.to_string(),
            parent: row.parent.map(|h| h.to_string()),
            root_tree: row.root_tree.to_string(),
            author_device: row.author_device,
            author_pubkey_hex: hex::encode(row.author_pubkey),
            timestamp: row.timestamp,
            intent: row.intent,
            master_key_id: row.master_key_id,
            signature_hex: hex::encode(row.signature),
            payload: row.payload,
        },
        root_tree: entries
            .into_iter()
            .map(|e| ShowTreeEntry {
                name: e.name,
                kind: match e.kind {
                    TreeEntryKind::Blob => "blob".into(),
                    TreeEntryKind::Tree => "tree".into(),
                },
                mode: e.mode,
                target_hex: e.target.to_string(),
            })
            .collect(),
    };
    Ok(serde_json::to_value(reply).unwrap())
}

pub fn fsck(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let repo = inner.repo.as_ref().expect("unlocked");
    let report =
        run_fsck(repo.db(), repo.objects()).map_err(|e| err_to_response(e.into()))?;
    let reply = FsckReply {
        commits_checked: report.commits_checked as u64,
        trees_checked: report.trees_checked as u64,
        objects_checked: report.objects_checked as u64,
        orphan_objects: report
            .orphan_objects
            .iter()
            .map(|h| h.to_string())
            .collect(),
        problems: report.problems,
    };
    Ok(serde_json::to_value(reply).unwrap())
}

pub fn propose_doc_update(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ProposeDocUpdateArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("propose_doc_update args: {e}")))?;

    if args.files.is_empty() {
        return Err((ErrorKind::BadArgs, "files must be non-empty".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    // Validate every path BEFORE writing any so a bad input doesn't
    // leave a half-applied state.
    let resolved: Vec<(PathBuf, String, &DocFile)> = args
        .files
        .iter()
        .map(|f| {
            let resolved = validate_repo_path(&garden_root, &f.path)
                .map_err(|m| (ErrorKind::BadArgs, m))?;
            Ok::<_, (ErrorKind, String)>((resolved, f.path.clone(), f))
        })
        .collect::<std::result::Result<_, _>>()?;

    // Mark every target path in the suppress map BEFORE any IO so the
    // watcher (running in parallel) drops the events.
    for (abs, _, _) in &resolved {
        daemon.mark_self_write(abs.clone());
    }

    let mut written = 0usize;
    for (abs, _, doc) in &resolved {
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).map_err(|e| (ErrorKind::Io, e.to_string()))?;
        }
        std::fs::write(abs, &doc.content).map_err(|e| (ErrorKind::Io, e.to_string()))?;
        written += 1;
    }

    // Build memory_edit payload: { summary, files: [paths], project }.
    let payload = serde_json::json!({
        "summary": args.summary,
        "files": resolved.iter().map(|(_, rel, _)| rel.clone()).collect::<Vec<_>>(),
        "project": args.project,
    });
    let intent =
        Intent::new("memory_edit", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;

    let inner = &mut *inner;
    let hook = inner.layer_b.clone();
    let session = inner.session.as_ref().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
    let hash = repo
        .commit_workdir(session, intent)
        .map_err(|e| err_to_response(e.into()))?;

    Ok(serde_json::to_value(ProposeDocUpdateReply {
        hash: hash.to_string(),
        files_written: written,
    })
    .unwrap())
}

pub fn shutdown(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let mut inner = daemon.inner.lock().unwrap();
    inner.state = State::Stopping;
    let _ = inner.fuse.take();
    inner.session = None;
    inner.repo = None;
    Ok(serde_json::json!({ "stopped": true }))
}

pub fn migrate_finalize(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let _: MigrateFinalizeArgs = serde_json::from_value(args.clone()).unwrap_or_default();

    // Snapshot the bits we need before mutating state, then drop the
    // lock so the FUSE handlers can wind down without deadlocking.
    let (garden_root, state_dir, was_fuse) = {
        let inner = daemon.inner.lock().unwrap();
        require_unlocked(&inner)?;
        if !inner.config.is_fuse_mode() {
            return Err((
                ErrorKind::BadArgs,
                "migrate_finalize requires a FUSE-mode daemon (state_root must be set)".into(),
            ));
        }
        if inner.fuse.is_none() {
            return Err((
                ErrorKind::BadArgs,
                "FUSE not mounted — start the daemon with FUSE enabled before finalize".into(),
            ));
        }
        (
            inner.config.garden_root.clone(),
            inner.config.state_dir().to_path_buf(),
            inner.fuse.is_some(),
        )
    };

    // Step 1: drop the mount handle (unmounts).
    {
        let mut inner = daemon.inner.lock().unwrap();
        let _ = inner.fuse.take();
    }
    let unmounted = was_fuse;

    // Step 2: best-effort sweep of plaintext under garden_root,
    // skipping the legacy `.softfig/` directory (handled in step 3).
    let mut plaintext_skipped = Vec::new();
    let plaintext_deleted = crate::migrate::delete_tree_except(
        &garden_root,
        &[".softfig"],
        &mut plaintext_skipped,
    );

    // Step 3: delete the orphan `garden_root/.softfig/` tree. The
    // canonical state already lives at state_dir.
    let (old_state_deleted, old_state_skipped) =
        crate::migrate::delete_dir(&garden_root.join(".softfig"));

    // Step 4: remount FUSE on top of the now-empty garden_root.
    let remounted = {
        let mut inner = daemon.inner.lock().unwrap();
        let session = match inner.session.as_ref() {
            Some(s) => s.clone(),
            None => {
                return Err((
                    ErrorKind::Internal,
                    "session vanished mid-finalize".into(),
                ));
            }
        };
        if !inner.config.enable_fuse {
            true
        } else {
            let sink =
                crate::fuse_sink::AccumulatorSink::spawn(daemon.accumulator.clone());
            let sealed_q: Arc<dyn SealedQuery> = inner.layer_b.clone();
            match softfig_fuse::FuseMount::mount_with(
                &garden_root,
                &state_dir,
                session,
                sink,
                Some(sealed_q),
            ) {
                Ok(handle) => {
                    if let Some(repo) = inner.repo.as_mut() {
                        softfig_fuse::FuseMount::install_tip_callback(repo, &handle);
                    }
                    inner.fuse = Some(handle);
                    true
                }
                Err(e) => {
                    eprintln!("keeperd: migrate_finalize: remount failed: {e}");
                    false
                }
            }
        }
    };

    let reply = MigrateFinalizeReply {
        unmounted,
        plaintext_deleted,
        plaintext_skipped,
        old_state_deleted,
        old_state_skipped,
        remounted,
    };
    Ok(serde_json::to_value(reply).unwrap())
}

// ---- M2b: Layer B reveal + seal/unseal/list-sealed --------------------

pub fn vault_reveal(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: VaultRevealArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("vault_reveal args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Idle-window check: skip the prompt if a previous successful
    // reveal happened within `idle_seconds`.
    let idle_seconds = inner.config.reveal.idle_seconds;
    let now = Instant::now();
    let needs_prompt = match (idle_seconds, inner.last_reveal_at) {
        (0, _) => true,
        (_n, None) => true,
        (n, Some(prev)) => prev.elapsed().as_secs() > n,
    };

    if args.probe_only {
        let msg = if needs_prompt {
            "prompt_required"
        } else {
            "within_idle_window"
        };
        return Err((ErrorKind::IdleStatusOnly, msg.to_string()));
    }

    if needs_prompt {
        let pw = args
            .master_password
            .as_deref()
            .ok_or((ErrorKind::MasterPasswordRequired, "master password required".into()))?;
        let session = inner.session.as_ref().expect("unlocked").clone();
        session
            .verify_master_passphrase(pw.as_bytes())
            .map_err(|e| (ErrorKind::AuthFailed, e.to_string()))?;
    }

    // Validate the path. Sealed-path enforcement only applies to the
    // M2b whole-file reveal (id = None); M2c region reveal works on
    // any path that has an inline `<vault id="…">` tag with the
    // matching id.
    let garden_root = inner.config.garden_root.clone();
    let rel = validate_repo_path(&garden_root, &args.path)
        .map_err(|m| (ErrorKind::BadArgs, m))?;
    let rel_string = path_to_repo_rel_string(&garden_root, &rel)
        .ok_or((ErrorKind::BadArgs, "path outside garden root".into()))?;

    if let Some(id) = args.id.as_deref() {
        validate_reveal_id(id)?;
    }

    let layer_b_hook = inner.layer_b.clone();
    let is_whole_file_sealed = layer_b_hook.snapshot().is_sealed(&rel_string);

    // Resolve the blob via the tip view.
    let session = inner.session.as_ref().expect("unlocked").clone();
    let repo = inner.repo.as_ref().expect("unlocked");
    let tip = repo
        .tip()
        .map_err(|e| err_to_response(e.into()))?
        .ok_or((ErrorKind::SealedPathNotFound, "no commits yet".into()))?;
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;
    let blob_hash = resolve_path_in_tree(repo, &row.root_tree, &rel_string)?
        .ok_or((
            ErrorKind::SealedPathNotFound,
            format!("{rel_string}: not in tip tree"),
        ))?;
    let cipher = repo
        .objects()
        .get(&blob_hash)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;

    // Resolve the plaintext written to the temp file based on `id`:
    //   id = None && whole-file-sealed → existing M2b decrypt
    //   id = None && has inline regions → restore every region's
    //       plaintext in place; non-region bytes pass through
    //   id = None && no tags && not sealed → SealedPathNotFound
    //   id = Some(name) → look up region by id, decrypt body, write
    //       only the region's plaintext
    let plaintext: Vec<u8> = match (&args.id, is_whole_file_sealed) {
        (None, true) => session
            .decrypt_layer_b(&rel_string, &cipher)
            .map_err(|e| (ErrorKind::AuthFailed, format!("layer b decrypt: {e}")))?,
        (None, false) => {
            let layer_a = session
                .decrypt_blob(&cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("layer a decrypt: {e}")))?;
            let parser = layer_b::regions::parser_for(&rel_string);
            let spans = layer_b::regions::parse(parser, &layer_a, &session, &rel_string)
                .map_err(|e| {
                    (
                        ErrorKind::MalformedVaultTag,
                        format!("vault tag parse failed: {e}"),
                    )
                })?;
            if spans.is_empty() {
                return Err((
                    ErrorKind::SealedPathNotFound,
                    format!("{rel_string}: not sealed and no inline <vault> regions"),
                ));
            }
            // Restore every region's plaintext in place. For each
            // Ciphertext span, decrypt body and substitute. Plaintext
            // spans pass through unchanged.
            let mut subs: Vec<(std::ops::Range<usize>, Vec<u8>)> = Vec::new();
            for span in &spans {
                if span.kind == layer_b::regions::RegionKind::Ciphertext {
                    let b64 = &layer_a[span.body_byte_range.clone()];
                    let raw = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|e| {
                            (
                                ErrorKind::MalformedVaultTag,
                                format!("base64 decode failed: {e}"),
                            )
                        })?;
                    let pt = session
                        .decrypt_layer_b_region(&rel_string, &span.id, &raw)
                        .map_err(|e| {
                            (
                                ErrorKind::AuthFailed,
                                format!("region decrypt failed for id {:?}: {e}", span.id),
                            )
                        })?;
                    subs.push((span.body_byte_range.clone(), pt));
                }
            }
            layer_b::regions::with_substitutions(layer_a, &subs)
        }
        (Some(name), _) => {
            // Region reveal — load Layer A bytes, parse for the named
            // id, decrypt the body, return only that plaintext. Works
            // whether or not the whole file is sealed.
            let layer_a = if is_whole_file_sealed {
                session
                    .decrypt_layer_b(&rel_string, &cipher)
                    .map_err(|e| (ErrorKind::AuthFailed, format!("layer b decrypt: {e}")))?
            } else {
                session
                    .decrypt_blob(&cipher)
                    .map_err(|e| (ErrorKind::AuthFailed, format!("layer a decrypt: {e}")))?
            };
            let parser = layer_b::regions::parser_for(&rel_string);
            let spans = layer_b::regions::parse(parser, &layer_a, &session, &rel_string)
                .map_err(|e| {
                    (
                        ErrorKind::MalformedVaultTag,
                        format!("vault tag parse failed: {e}"),
                    )
                })?;
            let span = spans
                .into_iter()
                .find(|s| s.id == *name)
                .ok_or_else(|| {
                    (
                        ErrorKind::SealedPathNotFound,
                        format!("{rel_string}: no <vault id={name:?}> region"),
                    )
                })?;
            if span.kind == layer_b::regions::RegionKind::Plaintext {
                // Region body is not encrypted yet — return as-is so
                // the user can still see what's in there.
                layer_a[span.body_byte_range].to_vec()
            } else {
                let b64 = &layer_a[span.body_byte_range.clone()];
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|e| {
                        (
                            ErrorKind::MalformedVaultTag,
                            format!("base64 decode failed: {e}"),
                        )
                    })?;
                session
                    .decrypt_layer_b_region(&rel_string, name, &raw)
                    .map_err(|e| {
                        (
                            ErrorKind::AuthFailed,
                            format!("region decrypt failed for id {name:?}: {e}"),
                        )
                    })?
            }
        }
    };

    // Write 0600 temp file in XDG_RUNTIME_DIR. Caller `open()`s it.
    let temp_path = write_reveal_temp_file(&rel_string, args.id.as_deref(), &plaintext)
        .map_err(|e| (ErrorKind::Io, e))?;

    // Commit a `vault_reveal` audit intent. Failure to commit is fatal
    // — we'd rather not surface the temp path without the log entry.
    let unix_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let actor = "device:local".to_string();
    let intent =
        layer_b::vault_reveal_intent(&rel_string, &actor, unix_ts, args.id.as_deref())
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hook = inner.layer_b.clone();
    let session_ref = inner.session.as_ref().expect("unlocked");
    let repo = inner.repo.as_mut().expect("unlocked");
    let _guard =
        PriorTipGuard::install(&hook, repo, session_ref).map_err(err_to_response)?;
    repo.commit_workdir(session_ref, intent)
        .map_err(|e| err_to_response(e.into()))?;
    drop(_guard);
    inner.last_reveal_at = Some(now);

    let expires_at = if idle_seconds == 0 {
        unix_ts
    } else {
        unix_ts + idle_seconds as i64
    };
    Ok(serde_json::to_value(VaultRevealReply {
        temp_path: temp_path.to_string_lossy().into_owned(),
        expires_at,
    })
    .unwrap())
}

pub fn vault_seal(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: VaultSealArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("vault_seal args: {e}")))?;
    if args.pattern.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "empty pattern".into()));
    }
    // Refuse the commit at the boundary per open-question 4 lean:
    // malformed globs are rejected at edit time so the editor (FUSE
    // write or CLI verb) gets an immediate error.
    let _ = globset::Glob::new(&args.pattern)
        .map_err(|e| (ErrorKind::BadArgs, format!("invalid glob: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();
    let garden_root = inner.config.garden_root.clone();

    // Mark the on-disk sealed-paths.toml as a self-write so the
    // (state-root-targeted) watcher's accept filter skips it.
    daemon.mark_self_write(layer_b::sealed_paths_file_path(&state_dir));

    let added = layer_b::append_glob(&state_dir, &args.pattern)
        .map_err(err_to_response)?;

    // Reload the matcher and reinstall (Arc swap inside the hook).
    let hook = inner.layer_b.clone();
    hook.reload(&state_dir)
        .map_err(err_to_response)?;

    // Commit the schema_change.
    let intent = layer_b::schema_change_intent(
        "softfig-layer-b-impl",
        layer_b::SEALED_PATHS_CHANGED_KIND,
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner_mut = &mut *inner;
    let session = inner_mut.session.as_ref().expect("unlocked").clone();
    let repo = inner_mut.repo.as_mut().expect("unlocked");
    let schema_guard =
        PriorTipGuard::install(&hook, repo, &session).map_err(err_to_response)?;
    let schema_commit = repo
        .commit_workdir(&session, intent)
        .map_err(|e| err_to_response(e.into()))?;
    drop(schema_guard);

    let mut newly_sealed = Vec::new();
    let mut seal_commit: Option<String> = None;
    if added {
        let snapshot = hook.snapshot();
        newly_sealed = layer_b::enumerate_matching(&garden_root, &snapshot);
        if !newly_sealed.is_empty() {
            // Re-snapshot the tree: the blob encryptor (this same hook)
            // will route these paths through Layer B on this pass.
            let seal_intent = layer_b::vault_seal_intent(
                &newly_sealed,
                "sealed-paths.toml glob added",
            )
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
            let seal_guard =
                PriorTipGuard::install(&hook, repo, &session).map_err(err_to_response)?;
            let hash = repo
                .commit_workdir(&session, seal_intent)
                .map_err(|e| err_to_response(e.into()))?;
            drop(seal_guard);
            seal_commit = Some(hash.to_string());
        }
    }

    Ok(serde_json::to_value(VaultSealReply {
        schema_commit: schema_commit.to_string(),
        seal_commit,
        newly_sealed,
    })
    .unwrap())
}

pub fn vault_unseal(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: VaultUnsealArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("vault_unseal args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    daemon.mark_self_write(layer_b::sealed_paths_file_path(&state_dir));

    // Edit the file first, but DO NOT reload the matcher yet. Per the
    // locked picks, `unseal` must not bulk-decrypt previously-sealed
    // blobs — so we commit the `schema_change` while the old matcher
    // is still active. Its tree build still routes the now-deglobbed
    // paths through Layer B (same plaintext + same path-keyed subkey
    // → same blob hash, no new ciphertext written). Reload happens
    // afterward so future commits stop sealing.
    let removed = layer_b::remove_glob(&state_dir, &args.pattern)
        .map_err(err_to_response)?;

    let intent = layer_b::schema_change_intent(
        "softfig-layer-b-impl",
        layer_b::SEALED_PATHS_CHANGED_KIND,
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner_mut = &mut *inner;
    let hook = inner_mut.layer_b.clone();
    let session = inner_mut.session.as_ref().expect("unlocked");
    let repo = inner_mut.repo.as_mut().expect("unlocked");
    let _guard = PriorTipGuard::install(&hook, repo, session).map_err(err_to_response)?;
    let schema_commit = repo
        .commit_workdir(session, intent)
        .map_err(|e| err_to_response(e.into()))?;
    drop(_guard);

    // Now swap the matcher to the new (smaller) glob set.
    inner.layer_b
        .reload(&state_dir)
        .map_err(err_to_response)?;

    Ok(serde_json::to_value(VaultUnsealReply {
        schema_commit: schema_commit.to_string(),
        removed,
    })
    .unwrap())
}

pub fn vault_list_sealed(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let snapshot = inner.layer_b.snapshot();
    let globs = snapshot.globs().to_vec();
    let garden_root = inner.config.garden_root.clone();
    let matching_files = layer_b::enumerate_matching(&garden_root, &snapshot);

    Ok(serde_json::to_value(VaultListSealedReply {
        globs,
        matching_files,
    })
    .unwrap())
}

// ---- helpers ----

/// Walk a tree's nested rows looking for the blob hash at
/// `repo_relative`. Returns `None` if the path doesn't exist or names
/// a directory.
pub(crate) fn resolve_path_in_tree(
    repo: &Repo,
    root_tree: &Hash,
    rel: &str,
) -> std::result::Result<Option<Hash>, (ErrorKind, String)> {
    let components: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Ok(None);
    }
    let mut current = *root_tree;
    for (i, name) in components.iter().enumerate() {
        let entries = repo
            .db()
            .get_tree(&current)
            .map_err(|e| err_to_response(KeeperError::Store(e)))?;
        let entry = entries.into_iter().find(|e| e.name == *name);
        let Some(entry) = entry else {
            return Ok(None);
        };
        let is_last = i + 1 == components.len();
        match entry.kind {
            TreeEntryKind::Blob if is_last => return Ok(Some(entry.target)),
            TreeEntryKind::Blob => return Ok(None),
            TreeEntryKind::Tree if is_last => return Ok(None),
            TreeEntryKind::Tree => current = entry.target,
        }
    }
    Ok(None)
}

fn write_reveal_temp_file(
    rel: &str,
    id: Option<&str>,
    plaintext: &[u8],
) -> std::result::Result<PathBuf, String> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    if !runtime_dir.exists() {
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| format!("create runtime dir: {e}"))?;
    }
    // Crude random suffix from nanos — sufficient for collision
    // avoidance in $XDG_RUNTIME_DIR; not a security boundary.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    // M2c: region reveals name the temp file after the region id
    // (`softfig-reveal-<id>-<rand>.txt`) so an op can tell which secret
    // they're holding when several reveals are open at once. Whole-file
    // reveals keep the M2b shape (`softfig-reveal-<pid>-<rand>.<ext>`).
    let path = match id {
        Some(name) => runtime_dir.join(format!("softfig-reveal-{name}-{nanos:08x}.txt")),
        None => {
            let ext = Path::new(rel)
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("bin");
            runtime_dir.join(format!("softfig-reveal-{pid}-{nanos:08x}.{ext}"))
        }
    };

    // Open with mode 0600 so the plaintext is readable only by the
    // running user.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts
        .open(&path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    use std::io::Write;
    f.write_all(plaintext)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all().ok();
    Ok(path)
}

/// Validate a `--id <id>` argument for `softfig reveal`. Mirrors the
/// charset / length rule the parser enforces — fails fast on the
/// daemon side so the CLI gets `BadArgs` instead of leaking malformed
/// ids into the audit log.
fn validate_reveal_id(id: &str) -> std::result::Result<(), (ErrorKind, String)> {
    if id.is_empty() {
        return Err((ErrorKind::BadArgs, "reveal --id must be non-empty".into()));
    }
    if id.len() > layer_b::regions::REGION_ID_MAX {
        return Err((
            ErrorKind::BadArgs,
            format!("reveal --id exceeds {} bytes", layer_b::regions::REGION_ID_MAX),
        ));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err((
            ErrorKind::BadArgs,
            format!("reveal --id {id:?}: charset must be [a-zA-Z0-9_-]+"),
        ));
    }
    Ok(())
}

pub(crate) fn path_to_repo_rel_string(garden_root: &Path, abs: &Path) -> Option<String> {
    abs.strip_prefix(garden_root)
        .ok()
        .and_then(|p| p.to_str())
        .map(|s| s.replace('\\', "/"))
}

pub(crate) fn require_unlocked(inner: &crate::daemon::DaemonInner) -> std::result::Result<(), (ErrorKind, String)> {
    match inner.state {
        State::Unlocked => Ok(()),
        State::Locked => Err((ErrorKind::VaultLocked, "vault is locked".into())),
        State::Stopping => Err((ErrorKind::Internal, "daemon stopping".into())),
    }
}

pub(crate) fn validate_repo_path(garden_root: &Path, rel: &str) -> std::result::Result<PathBuf, String> {
    if rel.is_empty() {
        return Err("empty path".into());
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(format!("{rel}: must be repo-relative, got absolute"));
    }
    for c in p.components() {
        match c {
            Component::Normal(_) => {}
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("{rel}: must not contain '..'"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("{rel}: invalid component"));
            }
        }
    }
    let abs = garden_root.join(p);
    // Defense-in-depth: even after the component check, ensure the
    // resolved path is rooted under the garden.
    let canon_root = garden_root
        .canonicalize()
        .unwrap_or_else(|_| garden_root.to_path_buf());
    let canon_parent = abs
        .parent()
        .map(|p| {
            p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
        })
        .unwrap_or_else(|| canon_root.clone());
    if !canon_parent.starts_with(&canon_root) {
        return Err(format!("{rel}: resolves outside garden root"));
    }
    Ok(abs)
}

fn short_summary(payload_canon: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(payload_canon) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if let Some(s) = v.get("summary").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(s) = v.get("slug").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(arr) = v.get("files").and_then(|v| v.as_array()) {
        let names: Vec<String> = arr
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .take(3)
            .collect();
        return format!("[{}]", names.join(", "));
    }
    String::new()
}

#[allow(dead_code)]
fn project_label() -> &'static str {
    PROJECT
}
