//! M3b — read-only browse verbs (`list_tree`, `read_file`).
//!
//! Both serve garden content from the committed tip tree and apply the
//! same [`LayerBHook`](crate::layer_b::LayerBHook) projection the FUSE
//! read path uses, so the TUI (or any future remote frontend) can never
//! receive sealed plaintext: whole-file-sealed paths surface as
//! `[sealed:<path>]`, inline `<vault id="…">` regions as `[encrypted]`.
//!
//! Reads require Unlocked — decryption needs the session — but never
//! write, never commit, and never touch the suppression map.

use softfig_core::Repo;
use softfig_fuse::SealedQuery;
use softfig_ipc::verbs::{
    ListTreeArgs, ListTreeReply, ReadFileArgs, ReadFileReply, TreeEntry,
};
use softfig_ipc::ErrorKind;
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::is_layer_b;

use crate::daemon::{Daemon, KeeperError};
use crate::handlers::{
    path_to_repo_rel_string, require_unlocked, resolve_path_in_tree, validate_repo_path,
    HandlerResult,
};
use crate::server::err_to_response;

/// Soft cap on the bytes `read_file` returns. The garden is small text;
/// this only guards against a pathological blob wedging the UI.
const READ_FILE_MAX: usize = 512 * 1024;

pub fn list_tree(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ListTreeArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("list_tree args: {e}")))?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();
    let repo = inner.repo.as_ref().expect("unlocked");

    // No commits yet → empty garden.
    let tip = match repo.tip().map_err(|e| err_to_response(e.into()))? {
        Some(h) => h,
        None => {
            return Ok(serde_json::to_value(ListTreeReply { entries: vec![] }).unwrap())
        }
    };
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;

    // None / "" / "." = garden root.
    let rel = args.path.as_deref().unwrap_or("").trim_matches('/');
    let (tree_hash, prefix) = if rel.is_empty() || rel == "." {
        (row.root_tree, String::new())
    } else {
        validate_repo_path(&garden_root, rel).map_err(|m| (ErrorKind::BadArgs, m))?;
        let tree = resolve_dir_in_tree(repo, &row.root_tree, rel)?.ok_or((
            ErrorKind::NotFound,
            format!("{rel}: not a directory in tip tree"),
        ))?;
        (tree, rel.to_string())
    };

    let mut entries: Vec<TreeEntry> = repo
        .db()
        .get_tree(&tree_hash)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?
        .into_iter()
        .map(|e| {
            let path = if prefix.is_empty() {
                e.name.clone()
            } else {
                format!("{prefix}/{}", e.name)
            };
            TreeEntry {
                name: e.name,
                path,
                is_dir: matches!(e.kind, TreeEntryKind::Tree),
            }
        })
        .collect();

    // Dirs first, then files, each alphabetical — sorted daemon-side so
    // every frontend agrees on order.
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));

    Ok(serde_json::to_value(ListTreeReply { entries }).unwrap())
}

pub fn read_file(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: ReadFileArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("read_file args: {e}")))?;

    let inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;
    let garden_root = inner.config.garden_root.clone();

    let abs = validate_repo_path(&garden_root, &args.path)
        .map_err(|m| (ErrorKind::BadArgs, m))?;
    let rel = path_to_repo_rel_string(&garden_root, &abs)
        .ok_or((ErrorKind::BadArgs, "path outside garden root".into()))?;

    let hook = inner.layer_b.clone();
    let session = inner.session.as_ref().expect("unlocked").clone();
    let repo = inner.repo.as_ref().expect("unlocked");

    let tip = repo
        .tip()
        .map_err(|e| err_to_response(e.into()))?
        .ok_or((ErrorKind::NotFound, "no commits yet".into()))?;
    let row = repo
        .db()
        .get_commit(&tip)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;
    let blob_hash = resolve_path_in_tree(repo, &row.root_tree, &rel)?.ok_or((
        ErrorKind::NotFound,
        format!("{rel}: not a file in tip tree"),
    ))?;
    let cipher = repo
        .objects()
        .get(&blob_hash)
        .map_err(|e| err_to_response(KeeperError::Store(e)))?;

    let sealed = hook.snapshot().is_sealed(&rel);
    let bytes: Vec<u8> = if sealed {
        // Whole-file sealed: project the FUSE placeholder. Never decrypt
        // and return the plaintext of a sealed file.
        format!("[sealed:{rel}]\n").into_bytes()
    } else {
        let layer_a = if is_layer_b(&cipher) {
            session
                .decrypt_layer_b(&rel, &cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("layer b decrypt: {e}")))?
        } else {
            session
                .decrypt_blob(&cipher)
                .map_err(|e| (ErrorKind::AuthFailed, format!("layer a decrypt: {e}")))?
        };
        // Same inline-region redaction the FUSE read path applies
        // (`[encrypted]` bodies; `[malformed vault tag …]` on parse fail).
        hook.redact_regions(&rel, layer_a)
    };

    let raw_len = bytes.len();
    let mut content = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => format!("[binary file: {raw_len} bytes]"),
    };
    if content.len() > READ_FILE_MAX {
        let mut end = READ_FILE_MAX;
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        content.truncate(end);
        content.push_str("\n[… truncated]");
    }

    Ok(serde_json::to_value(ReadFileReply {
        path: rel,
        content,
        sealed,
    })
    .unwrap())
}

/// Walk to the tree hash for a directory path. Returns `None` if the path
/// doesn't exist or names a blob (file) rather than a directory.
fn resolve_dir_in_tree(
    repo: &Repo,
    root_tree: &Hash,
    rel: &str,
) -> std::result::Result<Option<Hash>, (ErrorKind, String)> {
    let mut current = *root_tree;
    for name in rel.split('/').filter(|c| !c.is_empty()) {
        let entries = repo
            .db()
            .get_tree(&current)
            .map_err(|e| err_to_response(KeeperError::Store(e)))?;
        let Some(entry) = entries.into_iter().find(|e| e.name == name) else {
            return Ok(None);
        };
        match entry.kind {
            TreeEntryKind::Tree => current = entry.target,
            TreeEntryKind::Blob => return Ok(None),
        }
    }
    Ok(Some(current))
}
