//! Per-verb handlers. Each takes the shared daemon handle and the raw
//! args `Value`, returns either the success-data `Value` or an
//! (ErrorKind, message) pair.

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use softfig_vcs::{fsck as run_fsck, log_collect, Intent, Repo};
use softfig_fuse::SealedQuery;
use softfig_ipc::verbs::{
    CommitArgs, CommitReply, DiscoverListReply, FsckReply, HostedChain, LogArgs, LogEntry, LogReply,
    MigrateFinalizeArgs, MigrateFinalizeReply, PairBeginArgs, PairBeginReply,
    PairConfirmArgs, PairConfirmReply, PairListReply, PairPeer, PairRemoveArgs,
    PairRemoveReply, PendingPairing, RelockMintArgs, RelockMintReply, RelockRedeemArgs,
    RelockRedeemReply, ReplaceFileArgs, ReplaceFileReply,
    ReplicaGrantArgs, ReplicaGrantReply, ReplicaRevokeArgs, ReplicaRevokeReply,
    ReplicaStatusReply, SharedSubtreeAddArgs, SharedSubtreeAddReply, SharedSubtreeInfo,
    SharedSubtreeListReply, SharedSubtreeRemoveArgs, SharedSubtreeRemoveReply,
    SharedSubtreeToggleArgs, SharedSubtreeToggleReply,
    ShowArgs, ShowCommit, ShowReply, ShowTreeEntry, StatusReply, UnlockArgs,
    UnlockReply, VaultListSealedReply, VaultRevealArgs, VaultRevealReply,
    VaultSealArgs, VaultSealReply, VaultUnsealArgs, VaultUnsealReply,
};
use softfig_ipc::ErrorKind;
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::{RelockToken, Vault, RELOCK_TTL_SECS};

use crate::daemon::{Daemon, KeeperError};
use crate::layer_b::{self, LayerBHook, SealedPaths};
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
    // Growlight: surface an armed relock token (lazily prunes an expired one).
    let relock_expires_at =
        crate::relock::pending_expires_at(inner.config.state_dir(), unix_now());
    let reply = StatusReply {
        state: inner.state.label().to_string(),
        tip: tip_hex,
        garden_root: inner.config.garden_root.display().to_string(),
        protocol_version: softfig_ipc::PROTOCOL_VERSION,
        relock_pending: relock_expires_at.is_some(),
        relock_expires_at,
        shared_key_divergence: inner.last_shared_key_divergence.clone(),
    };
    Ok(serde_json::to_value(reply).unwrap())
}

/// Current unix time in seconds (saturating at 0 before the epoch).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

    establish_session_locked(daemon, &mut inner, session)?;
    drop(inner);
    apply_garden_config(daemon);
    start_net_if_enabled(daemon);
    crate::growlight_unit::apply_fleet_gate(daemon);

    Ok(serde_json::to_value(UnlockReply {
        state: State::Unlocked.label().to_string(),
    })
    .unwrap())
}

/// Build the live daemon state from a freshly-unlocked `VaultSession`: open the
/// repo, wire the Layer B hook as blob-encryptor + sealed-query, mount FUSE,
/// and flip to `Unlocked`. Shared by `unlock` (passphrase/recovery) and
/// `relock_redeem` so every route to Unlocked lands an identical session —
/// masters / identity / transport / FUSE all brought up the same way. The
/// caller holds `inner` and is responsible for the `start_net_if_enabled`
/// tail (which must drop the lock across thread spawns).
fn establish_session_locked(
    daemon: &Daemon,
    inner: &mut crate::daemon::DaemonInner,
    session: softfig_vault::VaultSession,
) -> std::result::Result<(), (ErrorKind, String)> {
    let garden_root = inner.config.garden_root.clone();
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
        // M5c slice 003 — derive the union-mount registry from the in-garden
        // allow-list (`config/shared-subtrees.toml` + local toggle sidecar).
        // Absent/empty ⇒ device_only ⇒ byte-identical to today.
        let registry = load_chain_registry(&repo, &session_arc, &state_dir);
        // M5d slice 002 — prime the encrypt router with the keyed chains.
        hook.set_shared_chain_keys(&registry);
        match softfig_fuse::FuseMount::mount_with(
            &garden_root,
            &state_dir,
            session_arc.clone(),
            sink,
            Some(sealed_q),
            registry,
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
    } else if inner.config.fuse_attach_unmounted {
        // Headless test seam (slice 007): the full FUSE state machine —
        // overlay staging, union view, registry hot-swap, commit routing —
        // with no kernel mount, so integration tests exercise the production
        // FUSE paths (and verbs gated on a live mount) without `/dev/fuse`.
        let sink = crate::fuse_sink::AccumulatorSink::spawn(daemon.accumulator.clone());
        let sealed_q: Arc<dyn SealedQuery> = hook.clone();
        let registry = load_chain_registry(&repo, &session_arc, &state_dir);
        hook.set_shared_chain_keys(&registry);
        match softfig_fuse::FuseMount::attach_unmounted(
            &garden_root,
            &state_dir,
            session_arc.clone(),
            sink,
            Some(sealed_q),
            registry,
        ) {
            Ok(handle) => {
                softfig_fuse::FuseMount::install_tip_callback(&mut repo, &handle);
                Some(handle)
            }
            Err(e) => {
                return Err((
                    ErrorKind::Io,
                    format!("fuse attach (test seam) at {}: {e}", garden_root.display()),
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
    Ok(())
}

/// Overlay the in-garden `config/keeper.toml` (`[net]`/`[relay]`/`[replica]`/
/// `[reveal]`) onto the running config once the session is up and FUSE is
/// mounted — must run *after* `establish_session_locked` (so the file is
/// readable through the mount) and *before* `start_net_if_enabled` (which reads
/// `config.net`). An absent file leaves the boot-time pointer values in place
/// (the non-migrated path); a parse error logs and does the same rather than
/// failing the unlock. Reads the file with no lock held (FUSE serves it on its
/// own threads), then locks `inner` only to apply.
fn apply_garden_config(daemon: &Daemon) {
    let garden_root = {
        let inner = daemon.inner.lock().unwrap();
        inner.config.garden_root.clone()
    };
    match crate::keeper_toml::GardenConfig::load(&garden_root) {
        Ok(Some(gc)) => {
            daemon.inner.lock().unwrap().config.apply_garden_config(gc);
        }
        Ok(None) => {}
        Err(e) => eprintln!(
            "keeperd: config/keeper.toml load failed ({e}); using pointer/default values"
        ),
    }
}

/// M5a-4: host the softfig-net instance (inbound listener + mDNS + optional
/// relay) for cross-device pairing/reconnect, if `[net] enabled` and the
/// `enable_net` runtime flag are both on. Best-effort — a bind/mDNS failure
/// never fails the unlock. Locks `inner` itself and drops the lock across the
/// thread spawns (the inbound loop parks via the daemon handle).
fn start_net_if_enabled(daemon: &Daemon) {
    let inner = daemon.inner.lock().unwrap();
    if !daemon_enable_net(&inner) {
        return;
    }
    let session = match inner.session.as_ref() {
        Some(s) => s.clone(),
        None => return,
    };
    let name = crate::net::device_name(&inner.config);
    let local = crate::net::build_local_device(&session, name);
    let config = inner.config.clone();
    // Load the live ring through the WorkTree while we still hold `inner`
    // (mount-safe, in-memory in FUSE mode), then drop the lock so the network
    // setup — binds, mDNS, relay — runs entirely off the daemon mutex.
    let state_dir = config.state_dir().to_path_buf();
    let ring = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        crate::net::load_ring(&wt, &state_dir).unwrap_or_default()
    };
    drop(inner);
    let runtime = crate::net::NetRuntime::start(daemon, &config, local, ring);
    daemon.inner.lock().unwrap().net = Some(runtime);
}

/// Whether the net host should start: the user's `[net] enabled` AND the
/// `enable_net` runtime flag (the latter off in tests).
fn daemon_enable_net(inner: &crate::daemon::DaemonInner) -> bool {
    inner.config.enable_net && inner.config.net.enabled
}

/// Growlight relock — mint. Wrap the live KEK under a one-time token and write
/// the blob to tmpfs so an unattended daemon restart can resume this session.
/// Requires Unlocked **and** `[growlight] allow_relock` (the human's opt-in;
/// the agent cannot self-enable it). `persist=false` returns the token hex in
/// the reply (held in the `cycle` CLI's RAM); `persist=true` writes it to a
/// second `0600` tmpfs file and returns the path.
pub fn relock_mint(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: RelockMintArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("relock_mint args: {e}")))?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    if !inner.config.growlight.allow_relock {
        return Err((
            ErrorKind::RelockDisabled,
            "relock disabled: set [growlight] allow_relock = true in keeper.toml".into(),
        ));
    }

    let state_dir = inner.config.state_dir().to_path_buf();
    let session = inner.session.as_ref().expect("unlocked").clone();
    let now = unix_now();
    let (token, blob) = session
        .mint_relock(now, RELOCK_TTL_SECS)
        .map_err(|e| (ErrorKind::Internal, format!("mint relock: {e}")))?;

    let blob_path = crate::relock::blob_path(&state_dir)
        .ok_or((ErrorKind::Internal, "vault not initialized".into()))?;
    crate::relock::write_secret_file(&blob_path, &blob.encode())
        .map_err(|e| (ErrorKind::Io, format!("write relock blob: {e}")))?;

    let mut reply = RelockMintReply {
        persisted: args.persist,
        expires_at: blob.expires_at,
        blob_path: blob_path.display().to_string(),
        token: None,
        token_path: None,
    };
    if args.persist {
        let token_path = crate::relock::token_path(&state_dir)
            .ok_or((ErrorKind::Internal, "vault not initialized".into()))?;
        crate::relock::write_secret_file(&token_path, token.to_hex().as_bytes())
            .map_err(|e| (ErrorKind::Io, format!("write relock token: {e}")))?;
        reply.token_path = Some(token_path.display().to_string());
    } else {
        reply.token = Some(token.to_hex());
    }

    eprintln!(
        "keeperd: relock token minted (persisted={}, expires_at={})",
        args.persist, blob.expires_at
    );
    Ok(serde_json::to_value(reply).unwrap())
}

/// Growlight relock — redeem. On a freshly-restarted (Locked) daemon, unwrap
/// the KEK from the tmpfs blob with the token and rebuild the session exactly
/// as `unlock` does. `token` absent = `cycle`/`relock` (the daemon reads its own
/// persisted token file); `token` present redeems an in-RAM token (hex held in
/// CLI RAM). The blob (and any persisted token) is deleted on success — single
/// use.
pub fn relock_redeem(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: RelockRedeemArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("relock_redeem args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    match inner.state {
        State::Locked => {}
        State::Unlocked => {
            // Already unlocked — nothing to redeem. Leave the blob to prune.
            return Ok(serde_json::to_value(RelockRedeemReply {
                state: State::Unlocked.label().to_string(),
            })
            .unwrap());
        }
        State::Stopping => return Err((ErrorKind::Internal, "daemon stopping".into())),
    }

    let state_dir = inner.config.state_dir().to_path_buf();
    let blob_path = crate::relock::blob_path(&state_dir)
        .ok_or((ErrorKind::NotFound, "vault not initialized".into()))?;
    let blob_bytes = std::fs::read(&blob_path).map_err(|_| {
        (
            ErrorKind::NotFound,
            "no relock token armed (mint one first, or it expired)".into(),
        )
    })?;

    // Token source: the hex in args (cycle), else the daemon's own persisted
    // token file (relock). The persisted path is daemon-derived, so a caller
    // can never point the redeem at an arbitrary file.
    let token = match args.token.as_deref() {
        Some(hex) => RelockToken::from_hex(hex)
            .map_err(|e| (ErrorKind::BadArgs, format!("relock token: {e}")))?,
        None => {
            let token_path = crate::relock::token_path(&state_dir)
                .ok_or((ErrorKind::NotFound, "vault not initialized".into()))?;
            let hex = std::fs::read_to_string(&token_path).map_err(|_| {
                (
                    ErrorKind::NotFound,
                    "no persisted relock token (mint with persist, or pass the token)".into(),
                )
            })?;
            RelockToken::from_hex(hex.trim())
                .map_err(|e| (ErrorKind::BadArgs, format!("persisted relock token: {e}")))?
        }
    };

    let vault = Vault::at_state_root(&state_dir);
    let session = vault
        .redeem_relock(&token, &blob_bytes, unix_now())
        .map_err(|e| match e {
            softfig_vault::VaultError::RelockExpired => {
                (ErrorKind::AuthFailed, "relock token expired".into())
            }
            other => (ErrorKind::AuthFailed, other.to_string()),
        })?;

    establish_session_locked(daemon, &mut inner, session)?;
    drop(inner);
    apply_garden_config(daemon);
    start_net_if_enabled(daemon);
    // Resume re-applies the gate: a fleet left running across the cycle is
    // re-confirmed (idempotent start), one not yet up arms now, and one whose gate
    // was flipped off between cycles is stopped (live disable, locked-decision 6).
    crate::growlight_unit::apply_fleet_gate(daemon);

    // Single-use: remove the blob + any persisted token now that it redeemed.
    crate::relock::remove_artifacts(&state_dir);
    eprintln!("keeperd: relock token redeemed; session resumed");

    Ok(serde_json::to_value(RelockRedeemReply {
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

    // FUSE-mode-safe commit: in FUSE mode this snapshots the in-memory
    // (tip ∪ overlay) tree rather than walking the mount under `inner`.
    let hash = crate::actions::commit_now(&mut inner, intent)?;
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

/// Break-glass verbatim file write — the narrowed/renamed
/// `propose_doc_update`. Writes one file with no convention stamping and
/// commits `memory_edit`. Callers should prefer the structural verbs.
pub fn replace_file(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReplaceFileArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("replace_file args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let abs = validate_repo_path(&garden_root, &args.path).map_err(|m| (ErrorKind::BadArgs, m))?;
    let rel = path_to_repo_rel_string(&garden_root, &abs)
        .ok_or((ErrorKind::BadArgs, "path outside garden root".into()))?;

    // Write through the worktree: in FUSE mode this stages into the overlay
    // (no self-write of the mount under `inner`); in disk mode it suppresses
    // the watcher event + writes. Scoped so its borrow ends before the commit.
    {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        // Phase 3 CAS: when the caller pinned an `expected_version`, the file
        // must still exist with that whole-file version, else stale-reject.
        // The read rides the worktree (no mount I/O under `inner`).
        if let Some(want) = &args.expected_version {
            let current = wt.read(&rel).map(|b| softfig_store::Hash::of(&b).to_hex());
            if current.as_deref() != Some(want.as_str()) {
                return Err((
                    ErrorKind::Conflict,
                    format!("stale: {rel} changed since version {want} — re-read and retry"),
                ));
            }
        }
        wt.write(&rel, args.content.as_bytes())?;
    }

    let version = softfig_store::Hash::of(args.content.as_bytes()).to_hex();
    let payload = serde_json::json!({ "path": args.path });
    let intent =
        Intent::new("memory_edit", payload).map_err(|e| (ErrorKind::Internal, e.to_string()))?;

    // FUSE-mode-safe commit: snapshot the in-memory tree rather than walking
    // the mount under `inner`.
    let hash = crate::actions::commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(ReplaceFileReply {
        path: args.path,
        hash: hash.to_string(),
        version,
    })
    .unwrap())
}

pub fn shutdown(_daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    // Ack-before-teardown: just return the ack. The connection handler runs the
    // graceful teardown (`request_shutdown`) only AFTER this reply is flushed to
    // the client (see `server::handle_connection`). Tearing down here — the old
    // order — could close the socket and flip the daemon to `Stopping` (ending
    // the accept loop, racing `main` to process exit) before the ack reached the
    // wire, so the client saw "closed without replying" and a `daemon cycle`
    // aborted pre-redeem, stranding the daemon Locked (incident 20260622).
    // SIGTERM/SIGINT and `DaemonHandle::drop` still call `request_shutdown`.
    Ok(serde_json::json!({ "stopped": true }))
}

pub fn migrate_finalize(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let _: MigrateFinalizeArgs = serde_json::from_value(args.clone()).unwrap_or_default();

    // Snapshot the bits we need before mutating state, then drop the
    // lock so the FUSE handlers can wind down without deadlocking.
    let (garden_root, state_dir, was_fuse, reveal_idle) = {
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
            inner.config.reveal.idle_seconds,
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

    // Step 3.5: re-establish the discovery pointer. Step 3 removed
    // `garden_root/.softfig` wholesale, including the `keeper.toml` that
    // `KeeperConfig::discover` reads on the next daemon start. Without it a
    // rebooted daemon resolves to M1c-compat (no FUSE) and the migrated
    // garden never remounts — its ciphertext stays safe in `state_dir` but
    // orphaned, and `~/<garden>` comes up empty. Write a fresh pointer onto
    // the real (still-unmounted) garden root, mirroring the born-in-FUSE
    // layout. MUST precede the step-4 remount: once FUSE is back up, a
    // `garden_root/.softfig` write lands in the overlay, not on disk.
    let pointer = crate::keeper_toml::KeeperToml {
        state_root: Some(state_dir.clone()),
        reveal: crate::keeper_toml::RevealToml {
            idle_seconds: reveal_idle,
        },
        ..Default::default()
    };
    if let Err(e) = pointer.store(&garden_root) {
        eprintln!(
            "keeperd: migrate_finalize: FAILED to re-write \
             {}/.softfig/keeper.toml ({e}); the garden will NOT auto-FUSE-mount \
             after a restart until that pointer is restored (state_root = {})",
            garden_root.display(),
            state_dir.display()
        );
    }

    // Step 4: remount FUSE on top of the now-pointer-only garden_root.
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
            // M5c slice 003 — config-derived registry (see `load_chain_registry`).
            // Absent repo/config ⇒ default() = device_only ⇒ byte-identical.
            let registry = inner
                .repo
                .as_ref()
                .map(|r| load_chain_registry(r, &session, &state_dir))
                .unwrap_or_default();
            inner.layer_b.set_shared_chain_keys(&registry);
            match softfig_fuse::FuseMount::mount_with(
                &garden_root,
                &state_dir,
                session,
                sink,
                Some(sealed_q),
                registry,
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

/// Enumerate the tracked working-tree files matched by `sealed`. In FUSE mode
/// the file list comes from the driver's in-memory (tip ∪ overlay) state
/// ([`MountHandle::live_repo_paths`]); direct-mode / M1c-compat daemons (no
/// mount) fall back to the `garden_root` disk walk. Either way the daemon never
/// `WalkDir`-walks the mount it serves under `inner` (the 2026-06-21
/// commit-path deadlock).
fn enumerate_sealed(
    inner: &crate::daemon::DaemonInner,
    sealed: &SealedPaths,
) -> std::result::Result<Vec<String>, (ErrorKind, String)> {
    match inner.fuse.as_ref() {
        Some(mount) => {
            let paths = mount
                .live_repo_paths()
                .map_err(|e| (ErrorKind::Io, format!("live repo paths: {e}")))?;
            Ok(layer_b::enumerate_matching_from_paths(&paths, sealed))
        }
        None => Ok(layer_b::enumerate_matching(
            &inner.config.garden_root,
            sealed,
        )),
    }
}

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
            .decrypt_tracked_blob(&rel_string, &cipher)
            .map_err(|e| (ErrorKind::AuthFailed, format!("sealed decrypt: {e}")))?,
        (None, false) => {
            let layer_a = session
                .decrypt_tracked_blob(&rel_string, &cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("decrypt: {e}")))?;
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
            let layer_a = session
                .decrypt_tracked_blob(&rel_string, &cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("decrypt: {e}")))?;
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
    // Commit the audit intent from the in-memory snapshot (FUSE) / disk walk
    // (direct mode) — `commit_now` installs the `PriorTipGuard` and never
    // self-reads the mount under `inner`.
    crate::actions::commit_now(&mut inner, intent)?;
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

    // Mark the on-disk sealed-paths.toml as a self-write so the
    // (state-root-targeted) watcher's accept filter skips it.
    daemon.mark_self_write(layer_b::sealed_paths_file_path(&state_dir));

    let added = layer_b::append_glob(&state_dir, &args.pattern)
        .map_err(err_to_response)?;

    // Reload the matcher and reinstall (Arc swap inside the hook).
    let hook = inner.layer_b.clone();
    hook.reload(&state_dir)
        .map_err(err_to_response)?;

    // Commit the schema_change from the in-memory snapshot (FUSE) / disk walk
    // (direct mode) — `commit_now` installs the `PriorTipGuard` and never
    // self-reads the mount under `inner`. The reloaded matcher already seals the
    // newly-matched paths, so this commit re-encrypts them through Layer B.
    let intent = layer_b::schema_change_intent(
        "softfig-layer-b-impl",
        layer_b::SEALED_PATHS_CHANGED_KIND,
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let schema_commit = crate::actions::commit_now(&mut inner, intent)?;

    let mut newly_sealed = Vec::new();
    let mut seal_commit: Option<String> = None;
    if added {
        let snapshot = hook.snapshot();
        newly_sealed = enumerate_sealed(&inner, &snapshot)?;
        if !newly_sealed.is_empty() {
            // Re-snapshot the tree: the blob encryptor (this same hook)
            // will route these paths through Layer B on this pass.
            let seal_intent = layer_b::vault_seal_intent(
                &newly_sealed,
                "sealed-paths.toml glob added",
            )
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
            let hash = crate::actions::commit_now(&mut inner, seal_intent)?;
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

    // Commit while the OLD matcher is still active, from the in-memory snapshot
    // (FUSE) / disk walk (direct mode) — never self-reading the mount under
    // `inner`. The snapshot reconstructs each still-sealed file's plaintext (a
    // Layer B tip blob is decrypted under its subkey), and the old matcher
    // re-seals it to the identical blob (convergent), so no bulk-decrypt leaks.
    let intent = layer_b::schema_change_intent(
        "softfig-layer-b-impl",
        layer_b::SEALED_PATHS_CHANGED_KIND,
    )
    .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let schema_commit = crate::actions::commit_now(&mut inner, intent)?;

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
    let matching_files = enumerate_sealed(&inner, &snapshot)?;

    Ok(serde_json::to_value(VaultListSealedReply {
        globs,
        matching_files,
    })
    .unwrap())
}

// ---- M5a-4: network pairing (transport + trust ring) ------------------

pub fn pair_begin(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: PairBeginArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("pair_begin args: {e}")))?;
    let fp_query = normalize_fingerprint(&args.fingerprint)?;

    // Snapshot the LocalDevice + resolve the endpoint under the lock, then
    // release it for the *blocking* XX handshake (never hold the daemon mutex
    // across network IO).
    let (local, endpoint) = {
        let inner = daemon.inner.lock().unwrap();
        require_unlocked(&inner)?;
        let session = inner.session.as_ref().expect("unlocked").clone();
        let name = crate::net::device_name(&inner.config);
        let local = crate::net::build_local_device(&session, name);
        let endpoint = match &args.endpoint {
            Some(ep) => Some(ep.clone()),
            None => inner.net.as_ref().and_then(|n| n.resolve_endpoint(&fp_query)),
        };
        (local, endpoint)
    };
    let endpoint = endpoint.ok_or((
        ErrorKind::NotFound,
        format!("peer {fp_query} not discovered; pass --endpoint host:port"),
    ))?;

    let pending = crate::net::initiate_pairing(&local, &endpoint)
        .map_err(|e| (ErrorKind::PairFailed, format!("pairing {endpoint}: {e}")))?;

    // The XX handshake authenticated the peer; make sure it is the one asked
    // for (defends against dialing the wrong endpoint for a fingerprint).
    let peer = pending.peer();
    let actual_fp = peer.fingerprint();
    if !actual_fp.starts_with(&fp_query) {
        return Err((
            ErrorKind::PairFailed,
            format!("connected peer {actual_fp} does not match requested {fp_query}"),
        ));
    }
    let sas = pending.sas().grouped();
    let name = peer.name.clone();

    let parked = crate::net::ParkedPairing {
        sas: sas.clone(),
        fingerprint: actual_fp.clone(),
        name: name.clone(),
        created: Instant::now(),
        pending,
    };
    let pairing_id = daemon.inner.lock().unwrap().pending_pairs.park(parked);

    Ok(serde_json::to_value(PairBeginReply {
        pairing_id,
        sas,
        fingerprint: actual_fp,
        name,
    })
    .unwrap())
}

pub fn pair_confirm(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: PairConfirmArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("pair_confirm args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let parked = inner.pending_pairs.take(&args.pairing_id).ok_or((
        ErrorKind::NotFound,
        format!("unknown pairing_id {:?}", args.pairing_id),
    ))?;

    // The user confirmed the SAS matched; add the peer to the ring's
    // membership, which is the source of truth inside the garden. Load (with
    // the legacy fallback), upsert, then write `config/peers.toml` + commit
    // `peers_changed` + refresh the endpoint sidecar.
    let (_session, entry) = parked.pending.confirm();
    let fingerprint = entry.fingerprint();
    let name = entry.name.clone();
    let mut ring = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        crate::net::load_ring(&wt, &state_dir)
            .map_err(|e| (ErrorKind::Io, format!("load ring: {e}")))?
    };
    ring.upsert(entry);
    crate::net::write_and_commit_membership(daemon, &mut inner, &state_dir, &ring)?;

    // Mirror into the live ring so the inbound listener authorizes the new
    // peer's IK reconnects immediately.
    if let Some(net) = inner.net.as_ref() {
        net.sync_ring(&ring);
    }

    Ok(serde_json::to_value(PairConfirmReply { fingerprint, name }).unwrap())
}

pub fn pair_list(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let ring = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        crate::net::load_ring(&wt, &state_dir)
            .map_err(|e| (ErrorKind::Io, format!("load ring: {e}")))?
    };
    let peers = ring
        .peers()
        .iter()
        .map(|p| PairPeer {
            fingerprint: p.fingerprint(),
            name: p.name.clone(),
            transport_pubkey: hex::encode(p.transport_pubkey),
            endpoints: p.endpoints.clone(),
            paired_at: p.paired_at,
        })
        .collect();
    let pending = inner
        .pending_pairs
        .list()
        .into_iter()
        .map(|(pairing_id, sas, fingerprint, name)| PendingPairing {
            pairing_id,
            sas,
            fingerprint,
            name,
        })
        .collect();

    Ok(serde_json::to_value(PairListReply { peers, pending }).unwrap())
}

pub fn pair_remove(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: PairRemoveArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("pair_remove args: {e}")))?;
    let fp_query = normalize_fingerprint(&args.fingerprint)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let mut ring = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        crate::net::load_ring(&wt, &state_dir)
            .map_err(|e| (ErrorKind::Io, format!("load ring: {e}")))?
    };
    let matches: Vec<[u8; 32]> = ring
        .peers()
        .iter()
        .filter(|p| p.fingerprint().starts_with(&fp_query))
        .map(|p| p.device_id)
        .collect();
    let device_id = match matches.as_slice() {
        [] => {
            return Err((
                ErrorKind::NotFound,
                format!("no ring peer matching {fp_query}"),
            ))
        }
        [id] => *id,
        many => {
            return Err((
                ErrorKind::BadArgs,
                format!("ambiguous fingerprint {fp_query}: {} ring peers match", many.len()),
            ))
        }
    };
    let full_fp = hex::encode(device_id);
    let removed = ring.remove(&device_id);
    if removed {
        crate::net::write_and_commit_membership(daemon, &mut inner, &state_dir, &ring)?;
        if let Some(net) = inner.net.as_ref() {
            net.sync_ring(&ring);
        }
    }

    Ok(serde_json::to_value(PairRemoveReply {
        removed,
        fingerprint: full_fp,
    })
    .unwrap())
}

/// Pairing-UX Slice A: the LAN pick-list. Surfaces the mDNS discovery cache's
/// nearby-but-unpaired devices so the CLI/TUI can pair by name. Read-only; no
/// network IO (the browse loop fills the cache out of band).
pub fn discover_list(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let ring = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        crate::net::load_ring(&wt, &state_dir)
            .map_err(|e| (ErrorKind::Io, format!("load ring: {e}")))?
    };
    let local_fp = hex::encode(
        inner
            .session
            .as_ref()
            .expect("unlocked")
            .identity_pubkey()
            .to_bytes(),
    );

    let devices = match inner.net.as_ref() {
        Some(net) => net.discover_list(&ring, &local_fp),
        None => Vec::new(),
    };

    Ok(serde_json::to_value(DiscoverListReply { devices }).unwrap())
}

// ---- M5b: replication (zero-knowledge device-chain backup) ------------

pub fn replica_grant(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReplicaGrantArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("replica_grant args: {e}")))?;
    let fp_query = normalize_fingerprint(&args.fingerprint)?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    // You may only grant a *paired* peer (a ring member): resolve the query to a
    // single ring device-id, so a typo can't authorize a stranger.
    let full_fp = {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        resolve_ring_fingerprint(&wt, &state_dir, &fp_query)?
    };

    let mut ledger = crate::replica::GrantLedger::load(&state_dir)
        .map_err(|e| (ErrorKind::Io, format!("load replica ledger: {e}")))?;
    let granted = ledger.grant(&full_fp);
    if granted {
        ledger
            .save(&state_dir)
            .map_err(|e| (ErrorKind::Io, format!("save replica ledger: {e}")))?;
    }
    Ok(serde_json::to_value(ReplicaGrantReply {
        fingerprint: full_fp,
        granted,
    })
    .unwrap())
}

pub fn replica_revoke(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReplicaRevokeArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("replica_revoke args: {e}")))?;
    let fp_query = normalize_fingerprint(&args.fingerprint)?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let mut ledger = crate::replica::GrantLedger::load(&state_dir)
        .map_err(|e| (ErrorKind::Io, format!("load replica ledger: {e}")))?;
    // Revoke works against the ledger itself (not the ring) so an unpaired host
    // can still be cleaned up. Match the query as a full id or a unique prefix.
    let matches: Vec<String> = ledger
        .push_to
        .iter()
        .filter(|f| f.starts_with(&fp_query))
        .cloned()
        .collect();
    let full_fp = match matches.as_slice() {
        [] => {
            return Err((
                ErrorKind::NotFound,
                format!("no replication grant matching {fp_query}"),
            ))
        }
        [one] => one.clone(),
        many => {
            return Err((
                ErrorKind::BadArgs,
                format!("ambiguous fingerprint {fp_query}: {} grants match", many.len()),
            ))
        }
    };
    let revoked = ledger.revoke(&full_fp);
    if revoked {
        ledger
            .save(&state_dir)
            .map_err(|e| (ErrorKind::Io, format!("save replica ledger: {e}")))?;
    }
    Ok(serde_json::to_value(ReplicaRevokeReply {
        fingerprint: full_fp,
        revoked,
    })
    .unwrap())
}

pub fn replica_status(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();
    let replica_root = inner.config.replica_root();
    let host = inner.config.replica.host;

    let push_to = crate::replica::GrantLedger::load(&state_dir)
        .map_err(|e| (ErrorKind::Io, format!("load replica ledger: {e}")))?
        .push_to;

    // Reading the mirror dirs is filesystem-only (no network, no decryption), so
    // it is fine under the lock; the trees are tiny metadata reads.
    let hosted = crate::replica::list_hosted(&replica_root)
        .into_iter()
        .map(|m| HostedChain {
            fingerprint: m.fingerprint,
            name: m.name,
            tip: m.tip,
            height: m.height,
            objects: m.objects,
            bytes: m.bytes,
            last_sync: m.last_sync,
        })
        .collect();

    Ok(serde_json::to_value(ReplicaStatusReply {
        host,
        push_to,
        hosted,
    })
    .unwrap())
}

/// Resolve a fingerprint query (full or unique prefix) to a single ring
/// member's full device-id fingerprint, or an error if none / ambiguous.
fn resolve_ring_fingerprint(
    worktree: &crate::actions::WorkTree<'_>,
    state_dir: &std::path::Path,
    fp_query: &str,
) -> std::result::Result<String, (ErrorKind, String)> {
    let ring = crate::net::load_ring(worktree, state_dir)
        .map_err(|e| (ErrorKind::Io, format!("load ring: {e}")))?;
    let matches: Vec<String> = ring
        .peers()
        .iter()
        .map(|p| p.fingerprint())
        .filter(|f| f.starts_with(fp_query))
        .collect();
    match matches.as_slice() {
        [] => Err((
            ErrorKind::NotFound,
            format!("no paired peer matching {fp_query}; pair it first"),
        )),
        [one] => Ok(one.clone()),
        many => Err((
            ErrorKind::BadArgs,
            format!("ambiguous fingerprint {fp_query}: {} ring peers match", many.len()),
        )),
    }
}

/// Normalize a fingerprint argument: lowercase, validate as 1–64 hex chars
/// (a full device-id is 64; a unique prefix is accepted for `pair_remove`).
fn normalize_fingerprint(s: &str) -> std::result::Result<String, (ErrorKind, String)> {
    let fp = s.trim().to_ascii_lowercase();
    if fp.is_empty() || fp.len() > 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((
            ErrorKind::BadArgs,
            format!("invalid fingerprint {s:?}: expect 1–64 hex chars"),
        ));
    }
    Ok(fp)
}

// ---- helpers ----

/// Walk a tree's nested rows looking for the blob hash at
/// `repo_relative`. Returns `None` if the path doesn't exist or names
/// a directory.
/// Build the live [`softfig_vcs::ChainRegistry`] from the in-garden
/// shared-subtree allow-list (M5c slice 003). Two sources, deliberately split:
/// the **committed** membership (`config/shared-subtrees.toml`) is read from the
/// device chain's tip tree — the registry is needed *before* the FUSE mount
/// exists, so unlike `config/keeper.toml`/`config/peers.toml` (read through the
/// mount) it comes straight from the encrypted store; the per-device
/// enable/disable state merges in from the never-committed
/// `.softfig/shared-subtrees-local.toml` sidecar. Any absent file — or a
/// decode/parse failure, logged and treated as sharing-off — falls back to an
/// empty allow-list, i.e. [`softfig_vcs::ChainRegistry::device_only`]
/// (byte-identical to today).
pub(crate) fn load_chain_registry(
    repo: &Repo,
    session: &softfig_vault::VaultSession,
    state_dir: &Path,
) -> softfig_vcs::ChainRegistry {
    let membership = read_committed_shared_subtrees(repo, session).unwrap_or_default();
    let local = load_local_toggles(state_dir);
    softfig_vcs::ChainRegistry::from_shared_config(&membership, &local)
}

/// Fetch + decrypt the committed `config/shared-subtrees.toml` text from the
/// device chain tip. `Ok(None)` when there are no commits yet or the file is
/// absent from the tip tree; `Err` when the file (or the tip it lives in)
/// could not be read, decrypted, or decoded.
fn read_committed_shared_subtrees_text(
    repo: &Repo,
    session: &softfig_vault::VaultSession,
) -> std::result::Result<Option<String>, String> {
    let rel = shared_subtrees_rel();
    let Some(tip) = repo.tip().map_err(|e| format!("read device tip: {e}"))? else {
        return Ok(None);
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| format!("read tip commit: {e}"))?;
    let Some(blob) = resolve_path_in_tree(repo, &row.root_tree, &rel).map_err(|(_, e)| e)? else {
        return Ok(None);
    };
    let cipher = repo
        .objects()
        .get(&blob)
        .map_err(|e| format!("read {rel} blob: {e}"))?;
    // The config lives under `config/`, not a sealed path, but decode any
    // container defensively so a future seal can't silently break the router.
    let plain = session
        .decrypt_tracked_blob(&rel, &cipher)
        .map_err(|e| format!("decrypt {rel}: {e}"))?;
    String::from_utf8(plain)
        .map(Some)
        .map_err(|_| format!("{rel} is not UTF-8"))
}

/// Read + decrypt + parse a committed shared-ceremony transcript record for
/// `key_id` from the device chain tip (M5d slice 003 rotation trigger). Mirrors
/// [`read_committed_shared_subtrees_text`]: resolve the record's committed path
/// ([`crate::ceremony::ceremony_record_rel`]), fetch its blob, decrypt under the
/// tracked-blob path, parse. `Ok(None)` when there are no commits yet or the
/// record is absent (a key whose transcript this device never committed). The
/// caller judges staleness from the parsed transcript's member set; this only
/// reads it back — `Transcript::verify` re-checks it from first principles when
/// a rotation actually consumes it.
pub(crate) fn read_committed_transcript(
    repo: &Repo,
    session: &softfig_vault::VaultSession,
    key_id: &str,
) -> std::result::Result<Option<softfig_net::ceremony::Transcript>, String> {
    let rel = crate::ceremony::ceremony_record_rel(key_id);
    let Some(tip) = repo.tip().map_err(|e| format!("read device tip: {e}"))? else {
        return Ok(None);
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| format!("read tip commit: {e}"))?;
    let Some(blob) = resolve_path_in_tree(repo, &row.root_tree, &rel).map_err(|(_, e)| e)? else {
        return Ok(None);
    };
    let cipher = repo
        .objects()
        .get(&blob)
        .map_err(|e| format!("read {rel} blob: {e}"))?;
    let plain = session
        .decrypt_tracked_blob(&rel, &cipher)
        .map_err(|e| format!("decrypt {rel}: {e}"))?;
    let text = String::from_utf8(plain).map_err(|_| format!("{rel} is not UTF-8"))?;
    crate::ceremony::parse_transcript_record(&text).map(Some)
}

/// The **read/compose** view of the committed membership (registry derivation,
/// `list`, toggle membership checks). `None` when there are no commits yet or
/// the file is absent; a present-but-broken file logs and yields `None`
/// (fail-safe = sharing off). Parses leniently so a newer-schema file with
/// additive fields still composes what this version understands (slice 007).
fn read_committed_shared_subtrees(
    repo: &Repo,
    session: &softfig_vault::VaultSession,
) -> Option<softfig_vcs::SharedSubtreesConfig> {
    let rel = shared_subtrees_rel();
    let text = match read_committed_shared_subtrees_text(repo, session) {
        Ok(text) => text?,
        Err(e) => {
            eprintln!("keeperd: {rel} unreadable ({e}); shared subtrees off");
            return None;
        }
    };
    match softfig_vcs::SharedSubtreesConfig::from_toml_str_lenient(&text) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("keeperd: {rel} parse failed ({e}); shared subtrees off");
            None
        }
    }
}

/// The **mutation** read (slice 007, interim-review finding 5): `add`/`remove`
/// rewrite the membership file, so a present-but-unreadable — or newer-schema,
/// the strict parse is `deny_unknown_fields` — file must hard-error instead of
/// defaulting to empty: an `.unwrap_or_default()` here would turn one corrupt
/// read into a committed allow-list wipe (and a lenient rewrite would silently
/// drop fields this daemon doesn't understand). Only a genuinely-absent file
/// (or a repo with no commits yet) may start from an empty allow-list.
pub(crate) fn read_committed_shared_subtrees_for_mutation(
    repo: &Repo,
    session: &softfig_vault::VaultSession,
) -> std::result::Result<softfig_vcs::SharedSubtreesConfig, (ErrorKind, String)> {
    let rel = shared_subtrees_rel();
    let text = read_committed_shared_subtrees_text(repo, session).map_err(|e| {
        (
            ErrorKind::Io,
            format!("could not read committed {rel} ({e}); refusing to modify shared-subtree membership"),
        )
    })?;
    match text {
        None => Ok(softfig_vcs::SharedSubtreesConfig::default()),
        Some(text) => softfig_vcs::SharedSubtreesConfig::from_toml_str(&text).map_err(|e| {
            (
                ErrorKind::Internal,
                format!(
                    "{rel} did not parse strictly ({e}); refusing to rewrite a membership file \
                     this daemon does not fully understand"
                ),
            )
        }),
    }
}

/// Load the per-device local-toggle sidecar (`.softfig/shared-subtrees-local.toml`,
/// never committed — same `.softfig/` home as the peers endpoint cache). Absent
/// ⇒ nothing disabled; present-but-broken logs and yields defaults.
fn load_local_toggles(state_dir: &Path) -> softfig_vcs::LocalToggles {
    let path = state_dir
        .join(".softfig")
        .join(softfig_vcs::LOCAL_TOGGLES_FILE);
    match std::fs::read_to_string(&path) {
        Ok(raw) => softfig_vcs::LocalToggles::from_toml_str(&raw).unwrap_or_else(|e| {
            eprintln!(
                "keeperd: {} parse failed ({e}); no local toggles",
                path.display()
            );
            softfig_vcs::LocalToggles::default()
        }),
        // Absent sidecar is the common case (nothing disabled).
        Err(_) => softfig_vcs::LocalToggles::default(),
    }
}

// ---- M5c slice 003: shared-subtree lifecycle -------------------------------
//
// Two control axes, deliberately split ([[decision-softfig-shared-subtrees-impl]]
// pick 3): `add`/`remove` edit the committed, ring-membership file
// `config/shared-subtrees.toml` (the collaborative key ceremony hangs off the
// add's commit — the m5d net reconcile sweep runs it and fills `key_id`);
// `enable`/`disable` flip ONLY the never-committed
// `.softfig/shared-subtrees-local.toml` sidecar, so the on/off toggle is
// provably ceremony-free (no membership/key_id/commit side-effect).
// After any change the mount's registry is hot-swapped so the union view
// recomposes live (a no-op in non-FUSE mode; re-derived at the next mount).

/// Repo-relative path of the committed membership file (`config/shared-subtrees.toml`).
pub(crate) fn shared_subtrees_rel() -> String {
    format!(
        "{}/{}",
        crate::keeper_toml::CONFIG_DIR,
        softfig_vcs::SHARED_SUBTREES_FILE
    )
}

/// Persist the per-device local-toggle sidecar (never committed; lives in the
/// state dir's `.softfig/`, next to the peers endpoint cache). Written
/// tmp+rename (slice 007, interim-review finding 11): the sidecar is the only
/// record of which shares this device disabled, and a crash-truncated file
/// fails *open* — the broken-parse fallback is "nothing disabled", silently
/// re-enabling every disabled share. The rename makes the swap atomic; the
/// single-writer daemon mutex makes the fixed tmp name safe.
fn save_local_toggles(
    state_dir: &Path,
    local: &softfig_vcs::LocalToggles,
) -> std::result::Result<(), (ErrorKind, String)> {
    let dir = state_dir.join(".softfig");
    std::fs::create_dir_all(&dir).map_err(|e| (ErrorKind::Io, format!("create .softfig: {e}")))?;
    let path = dir.join(softfig_vcs::LOCAL_TOGGLES_FILE);
    let tmp = dir.join(format!("{}.tmp", softfig_vcs::LOCAL_TOGGLES_FILE));
    let toml = local
        .to_toml()
        .map_err(|e| (ErrorKind::Internal, format!("serialize local toggles: {e}")))?;
    std::fs::write(&tmp, toml).map_err(|e| (ErrorKind::Io, format!("write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| (ErrorKind::Io, format!("rename {} -> {}: {e}", tmp.display(), path.display())))
}

/// Validate an explicit share id: 1–64 chars of `[a-z0-9-]` (the slug charset,
/// safe as both a `chain/<id>` ref component and a config key), and not the
/// reserved device-chain id.
fn validate_share_id(raw: &str) -> std::result::Result<String, (ErrorKind, String)> {
    let id = raw.trim();
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && id != softfig_vcs::DEVICE_CHAIN_ID;
    if ok {
        Ok(id.to_string())
    } else {
        Err((
            ErrorKind::BadArgs,
            format!("invalid share id {raw:?}: expect 1–64 chars of [a-z0-9-], not the reserved device id"),
        ))
    }
}

/// Derive a default share id from a mount path's last component (slugified).
fn derive_share_id(mount_path: &str) -> std::result::Result<String, (ErrorKind, String)> {
    let last = mount_path.rsplit('/').find(|c| !c.is_empty()).unwrap_or("");
    let slug: String = last
        .chars()
        .map(|c| {
            let l = c.to_ascii_lowercase();
            if l.is_ascii_lowercase() || l.is_ascii_digit() {
                l
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    validate_share_id(&slug).map_err(|_| {
        (
            ErrorKind::BadArgs,
            format!("could not derive a share id from {mount_path:?}; pass an explicit id"),
        )
    })
}

/// Normalize a mount-path argument to a clean `/`-joined garden-relative prefix
/// (no leading/trailing slash, no `.`), rejecting the obviously-bad shapes early;
/// [`softfig_vcs::validate_share_add`] remains the authority for the machine-dir
/// denylist + disjointness.
fn normalize_mount_path(raw: &str) -> std::result::Result<String, (ErrorKind, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('/') {
        return Err((
            ErrorKind::BadArgs,
            format!("mount_path {raw:?} must be a non-empty garden-relative path"),
        ));
    }
    let comps: Vec<&str> = trimmed
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    if comps.is_empty() || comps.contains(&"..") {
        return Err((
            ErrorKind::BadArgs,
            format!("mount_path {raw:?} is not a clean garden-relative path"),
        ));
    }
    Ok(comps.join("/"))
}

/// Rebuild the live chain registry from the committed membership + local sidecar
/// and hot-swap it into the FUSE mount (if any) so the union view recomposes
/// live — and into the Layer B hook's shared-chain key router (M5d slice 002)
/// so a freshly keyed chain's next write seals under its `S`. In non-FUSE
/// (Disk / M1c-compat) mode only the router refresh matters — the registry is
/// re-derived from the same two sources at the next mount there.
pub(crate) fn refresh_mount_registry(inner: &crate::daemon::DaemonInner, state_dir: &Path) {
    let registry = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        load_chain_registry(repo, session, state_dir)
    };
    inner.layer_b.set_shared_chain_keys(&registry);
    if let Some(mount) = inner.fuse.as_ref() {
        mount.set_registry(registry);
    }
}

pub fn shared_subtree_add(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SharedSubtreeAddArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("shared_subtree_add args: {e}")))?;
    let mount_path = normalize_mount_path(&args.mount_path)?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    // Slice 007 (interim-review finding 14): without a union mount nothing
    // splits — writes under the "shared" path would fold into the device chain
    // and reach its backup replicas. Refuse instead of leaking; a direct-mode
    // (no-FUSE / M1c-compat) daemon doesn't get a lesser version of sharing,
    // it gets none.
    if inner.fuse.is_none() {
        return Err((
            ErrorKind::BadArgs,
            "shared_subtree_add requires the FUSE union mount; in direct (M1c-compat) mode \
             shared-marked content would fold into the device chain and its replicas"
                .into(),
        ));
    }

    let state_dir = inner.config.state_dir().to_path_buf();

    // Current committed membership from the device tip. Mutation read: absent
    // ⇒ empty, unreadable/unparseable ⇒ hard error (never wipe — finding 5).
    let mut membership = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        read_committed_shared_subtrees_for_mutation(repo, session)?
    };

    // Reject a machine/reserved dir + any overlap with an existing share
    // (v1 = disjoint).
    softfig_vcs::validate_share_add(&membership, &mount_path)
        .map_err(|e| (ErrorKind::BadArgs, e.to_string()))?;

    let id = match args.id {
        Some(raw) => validate_share_id(&raw)?,
        None => derive_share_id(&mount_path)?,
    };
    if membership.contains(&id) {
        return Err((
            ErrorKind::BadArgs,
            format!("shared subtree id {id:?} already exists"),
        ));
    }
    let ref_name = format!("chain/{id}");

    // Slice 007 (finding 4) + m5c residual slice 009 (finding 1): a mount path
    // that already holds device content would vanish behind the graft — the new
    // chain's empty genesis shadows it and the next device commit's carve-out
    // drops it. Probe the composed (device tip ∪ FUSE overlay) view via the
    // WorkTree, not just the committed tip: a write staged through the live
    // mount inside the ~200ms flush-debounce window is real content the empty
    // graft would still swallow, and the tip-only walk missed it. Refuse; the
    // seed-genesis-from-device-subtree migration is a later slice.
    {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        // m5c-residual slice 011 (018 finding 10): a committed device FILE at an
        // *ancestor* of the mount path can't be descended through, so the
        // emptiness probe below reads the mount path as absent (Blob mid-path ->
        // Ok(false)) and the share is minted dead — untraversable behind the file.
        // Refuse a blob-ancestor path explicitly before the emptiness check.
        let mut prefix = String::new();
        for comp in mount_path.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(comp);
            if prefix == mount_path {
                break; // the leaf is the mount root itself — covered below
            }
            if wt.exists(&prefix) && !wt.is_dir(&prefix) {
                return Err((
                    ErrorKind::BadArgs,
                    format!(
                        "cannot share {mount_path:?}: ancestor {prefix:?} is a device file, so the \
                         mount would be untraversable — remove or move that file first"
                    ),
                ));
            }
        }
        if wt.exists(&mount_path) {
            return Err((
                ErrorKind::PathAlreadyExists,
                format!(
                    "{mount_path:?} already has device-chain content (committed or staged); \
                     migrating an existing subtree into a shared chain is not supported yet — \
                     share an empty path or move the content aside first"
                ),
            ));
        }
    }

    // Slice 007 (finding 10): the chain ref is created BEFORE the membership
    // commit, so a mid-add failure leaves a harmless orphan ref instead of a
    // committed membership row routing to a ref-less chain. A ref that already
    // exists — an orphan from a retried add, or a chain kept through a prior
    // `remove` (remove keeps the ref, and every ref is live for gc so its objects
    // survive — m5c-residual slice 011) — is reused as-is, never reset: re-adding
    // an id resumes its chain intact. No key ceremony here (m5d).
    let ref_exists = {
        let repo = inner.repo.as_ref().expect("unlocked");
        repo.tip_of(&ref_name)
            .map_err(|e| err_to_response(e.into()))?
            .is_some()
    };
    if !ref_exists {
        let genesis = Intent::init(format!("shared subtree {id} created"));
        crate::actions::commit_snapshot_to_now(
            &mut inner,
            &ref_name,
            softfig_vcs::WalkSnapshot::empty(),
            genesis,
        )?;
    }

    // Append the membership row with `key_id` empty and stage the config edit
    // through the WorkTree. The collaborative key ceremony (m5d) is deferred,
    // never an inline block: this commit signals the net reconcile loop, whose
    // ceremony sweep runs the commit-reveal with the peer and fills `key_id`
    // when members are next online (`net::reconcile_ceremonies`).
    membership.subtrees.push(softfig_vcs::SharedSubtreeEntry {
        id: id.clone(),
        mount_path: mount_path.clone(),
        ref_name: ref_name.clone(),
        key_id: None,
    });
    let toml = membership
        .to_toml()
        .map_err(|e| (ErrorKind::Internal, format!("serialize shared-subtrees: {e}")))?;
    {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        wt.write(&shared_subtrees_rel(), toml.as_bytes())?;
    }
    let payload = serde_json::json!({ "summary": format!("add shared subtree {id}") });
    let intent = Intent::new("shared_subtrees_changed", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    crate::actions::commit_now(&mut inner, intent)?;

    refresh_mount_registry(&inner, &state_dir);

    Ok(serde_json::to_value(SharedSubtreeAddReply {
        id,
        mount_path,
        ref_name,
    })
    .unwrap())
}

pub fn shared_subtree_remove(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: SharedSubtreeRemoveArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("shared_subtree_remove args: {e}")))?;
    let id = args.id.trim().to_string();

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    // Mutation read: absent ⇒ empty, unreadable/unparseable ⇒ hard error —
    // a lenient default here would let one corrupt read rewrite the file as
    // an empty allow-list (slice 007, finding 5).
    let mut membership = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        read_committed_shared_subtrees_for_mutation(repo, session)?
    };
    let before = membership.subtrees.len();
    membership.subtrees.retain(|s| s.id != id);
    let removed = membership.subtrees.len() != before;

    if removed {
        // Un-share = drop the membership row + commit. The chain ref + objects
        // are left in place and stay live for gc (retention is keyed on ref
        // existence — Repo::live_tips over db.list_refs, not registry membership),
        // so a later re-add of this id resumes the chain intact (m5c-residual
        // slice 011, contract (a): every ref is live). Reclaiming the objects
        // needs an explicit chain-drop verb (not built); this only stops
        // composing the subtree.
        let toml = membership
            .to_toml()
            .map_err(|e| (ErrorKind::Internal, format!("serialize shared-subtrees: {e}")))?;
        {
            let wt = crate::actions::WorkTree::new(daemon, &inner);
            wt.write(&shared_subtrees_rel(), toml.as_bytes())?;
        }
        let payload = serde_json::json!({ "summary": format!("remove shared subtree {id}") });
        let intent = Intent::new("shared_subtrees_changed", payload)
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        crate::actions::commit_now(&mut inner, intent)?;

        // Slice 007 (finding 9): purge the id from the local-toggle sidecar so
        // disable → remove → re-add is never born disabled. The membership
        // commit above already landed, so a sidecar write failure is logged
        // loudly rather than failing an op that did remove the member.
        let mut local = load_local_toggles(&state_dir);
        if local.enable(&id) {
            if let Err((_, e)) = save_local_toggles(&state_dir, &local) {
                eprintln!(
                    "keeperd: shared_subtree_remove {id}: could not purge the local toggle \
                     sidecar ({e}); a future re-add of this id would start disabled here"
                );
            }
        }
        refresh_mount_registry(&inner, &state_dir);
    }

    Ok(serde_json::to_value(SharedSubtreeRemoveReply { id, removed }).unwrap())
}

pub fn shared_subtree_enable(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    toggle_shared_subtree(daemon, args, false)
}

pub fn shared_subtree_disable(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    toggle_shared_subtree(daemon, args, true)
}

/// The shared body of `enable`/`disable`: flip ONLY the never-committed local
/// sidecar (no membership change, no commit, no ceremony), then live-recompose.
fn toggle_shared_subtree(daemon: &Daemon, args: serde_json::Value, disable: bool) -> HandlerResult {
    let args: SharedSubtreeToggleArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("shared_subtree toggle args: {e}")))?;
    let id = args.id.trim().to_string();

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    // Only a real member may be toggled, so a typo can't seed a phantom disable.
    let mount_path = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        let membership = read_committed_shared_subtrees(repo, session).unwrap_or_default();
        match membership.subtrees.iter().find(|s| s.id == id) {
            Some(entry) => entry.mount_path.clone(),
            None => {
                return Err((ErrorKind::NotFound, format!("no shared subtree with id {id:?}")));
            }
        }
    };

    // m5c residual slice 009 (finding 2a): enabling a share whose mount path
    // already holds content would shadow it behind the graft. While the share is
    // disabled the chain is transparent, so a write at/under the mount path
    // routes to the *device* chain; re-enabling grafts the shared chain over it
    // (`retain(!starts_with(prefix))`) and the committed device content vanishes
    // — the exact shape the add-guard prevents, reached through the sibling verb.
    // Probe the composed (device tip ∪ FUSE overlay) view; refuse the enable if
    // populated (disable has nothing to shadow, so it stays unguarded).
    if !disable {
        let wt = crate::actions::WorkTree::new(daemon, &inner);
        if wt.exists(&mount_path) {
            return Err((
                ErrorKind::PathAlreadyExists,
                format!(
                    "{mount_path:?} holds device-chain content written while the share was \
                     disabled; enabling would shadow it behind the shared graft — move it \
                     aside first"
                ),
            ));
        }
    }

    let mut local = load_local_toggles(&state_dir);
    let changed = if disable {
        local.disable(&id)
    } else {
        local.enable(&id)
    };
    if changed {
        save_local_toggles(&state_dir, &local)?;
        refresh_mount_registry(&inner, &state_dir);
    }

    Ok(serde_json::to_value(SharedSubtreeToggleReply {
        id,
        enabled: !disable,
        changed,
    })
    .unwrap())
}

pub fn shared_subtree_list(daemon: &Daemon, _args: serde_json::Value) -> HandlerResult {
    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let state_dir = inner.config.state_dir().to_path_buf();

    let membership = {
        let session = inner.session.as_ref().expect("unlocked");
        let repo = inner.repo.as_ref().expect("unlocked");
        read_committed_shared_subtrees(repo, session).unwrap_or_default()
    };
    let local = load_local_toggles(&state_dir);
    let subtrees = membership
        .subtrees
        .into_iter()
        .map(|e| {
            let enabled = !local.is_disabled(&e.id);
            SharedSubtreeInfo {
                id: e.id,
                mount_path: e.mount_path,
                ref_name: e.ref_name,
                enabled,
                key_id: e.key_id,
            }
        })
        .collect();

    Ok(serde_json::to_value(SharedSubtreeListReply { subtrees }).unwrap())
}

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
    // Defense-in-depth: even after the component check, assert the joined
    // path is lexically rooted under the garden. This is a PURE path
    // comparison and must NOT stat the filesystem. `canonicalize()` here
    // would round-trip through the FUSE mount under `inner` — exactly the
    // deadlock the commit-from-memory invariant exists to prevent
    // (decision-softfig-commit-from-memory). It is also unnecessary: the
    // component loop above already rejects `..`, absolute paths and root
    // components, so nothing can climb out of `garden_root` lexically; and
    // every caller resolves the returned path against the in-memory git
    // tree (path_to_repo_rel_string -> resolve_path_in_tree / WorkTree),
    // never the live mount, so on-disk symlink resolution would buy nothing.
    if !abs.starts_with(garden_root) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Intentionally a path that does NOT exist on disk: validate_repo_path is
    // purely lexical and must never stat the (mount) root — see the no-mount-IO
    // invariant in decision-softfig-commit-from-memory.
    fn root() -> PathBuf {
        PathBuf::from("/nonexistent/garden-root")
    }

    #[test]
    fn accepts_simple_relative_paths() {
        let r = root();
        assert_eq!(validate_repo_path(&r, "foo.md").unwrap(), r.join("foo.md"));
        assert_eq!(validate_repo_path(&r, "a/b/c.md").unwrap(), r.join("a/b/c.md"));
        // A leading ./ is allowed and normalizes away on the join.
        assert_eq!(validate_repo_path(&r, "./a/b.md").unwrap(), r.join("a/b.md"));
    }

    #[test]
    fn validates_without_touching_the_filesystem() {
        // The root does not exist; a purely lexical validator still succeeds.
        // This guards against ever reintroducing a canonicalize/exists() stat
        // of the mount under `inner`.
        let r = root();
        assert!(!r.exists());
        let abs = validate_repo_path(&r, "journal/x.md").unwrap();
        assert!(abs.starts_with(&r));
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_repo_path(&root(), "").unwrap_err().contains("empty"));
    }

    #[test]
    fn rejects_absolute() {
        let e = validate_repo_path(&root(), "/etc/passwd").unwrap_err();
        assert!(e.contains("absolute"), "{e}");
        // A bare root is also absolute.
        assert!(validate_repo_path(&root(), "/").unwrap_err().contains("absolute"));
    }

    #[test]
    fn rejects_parent_dir_traversal() {
        // Every form of `..` escape is rejected lexically, with or without an
        // interior prefix — the protection canonicalize used to backstop.
        for p in ["..", "../escape", "foo/../bar", "a/b/../../../etc/passwd"] {
            let e = validate_repo_path(&root(), p).unwrap_err();
            assert!(e.contains(".."), "{p}: {e}");
        }
    }
}
