//! `fuser::Filesystem` implementation.
//!
//! Reads materialize the union (tree-at-tip ∪ overlay). Writes update
//! the overlay and push a `DirtyEvent` into the daemon via the
//! [`DirtyEventSink`] callbacks. Commit lifecycle is owned by the
//! daemon — when its `DirtySetAccumulator` flushes, `commit_workdir`
//! walks our mount, reads our overlay+tip view, and (on success)
//! invokes the tip-changed callback which clears the overlay.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use softfig_core::Repo;
use softfig_store::{Db, Hash, ObjectStore, StorePaths};
use softfig_vault::VaultSession;

use crate::inodes::{InodeMap, ROOT_INODE};
use crate::overlay::{Overlay, OverlayEntry};
use crate::tree_view::{EntryKind, TreeView};
use crate::{DirtyEventSink, MountHandle, Result, SealedQuery};

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 512;

/// The mount runs with `DefaultPermissions`, so the kernel checks access
/// against each inode's owner *before* our handlers run. Present every
/// inode as owned by the keeper process (its effective uid/gid) so the
/// non-root daemon can write through its own mount.
///
/// `geteuid`/`getegid` are infallible FFI with no safety preconditions —
/// the only reason they're `unsafe` is the `extern "C"` boundary.
#[allow(unsafe_code)]
static OWNER_UID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::geteuid() });
#[allow(unsafe_code)]
static OWNER_GID: LazyLock<u32> = LazyLock::new(|| unsafe { libc::getegid() });

pub(crate) struct SharedState {
    /// Re-opened sqlite handle for read-only tip resolution. WAL means
    /// this is safe to use concurrently with the daemon's writer.
    db: Mutex<Db>,
    objects: ObjectStore,
    session: Arc<VaultSession>,
    pub(crate) inner: Mutex<Inner>,
    sink: Arc<dyn DirtyEventSink>,
    sealed: Option<Arc<dyn SealedQuery>>,
    /// M2c — cache of post-`redact_regions` bytes keyed by
    /// repo-relative path. Invalidated on `tip_changed` (broadcast).
    /// Per the M2c open-question 5 lean, unbounded for v1 (same policy
    /// as the M2a tree-view cache); LRU is a future optimization.
    redacted_cache: Mutex<HashMap<PathBuf, Vec<u8>>>,
}

impl std::fmt::Debug for SharedState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedState")
            .field("objects", &self.objects)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) inodes: InodeMap,
    pub(crate) tip: Option<Hash>,
    pub(crate) view: TreeView,
    pub(crate) overlay: Overlay,
}

impl SharedState {
    pub(crate) fn rotate_tip(&self) {
        let new_tip = {
            let db = self.db.lock().unwrap();
            db.try_get_ref(softfig_core::TIP_REF).ok().flatten()
        };
        // M2c — drop the redacted-content cache on every tip change;
        // the new tip may have introduced/removed/re-encrypted vault
        // regions, and the cache key (path) doesn't encode tip hash.
        self.redacted_cache.lock().unwrap().clear();
        let mut inner = self.inner.lock().unwrap();
        inner.tip = new_tip;
        inner.view = match inner.tip {
            Some(h) => {
                let db = self.db.lock().unwrap();
                let row = match db.get_commit(&h) {
                    Ok(r) => r,
                    Err(_) => {
                        inner.overlay.clear();
                        return;
                    }
                };
                drop(db);
                let db = self.db.lock().unwrap();
                TreeView::build(&db, &row.root_tree).unwrap_or_else(|_| TreeView::empty())
            }
            None => TreeView::empty(),
        };
        // Re-intern every path so freshly-introduced tip entries have
        // inodes ready for kernel lookups.
        for p in inner.view.paths().map(|p| p.to_path_buf()).collect::<Vec<_>>() {
            inner.inodes.intern(&p);
        }
        inner.overlay.clear();
    }
}

/// Public entry point. Builds the shared state, mounts at
/// `garden_root`, and returns the handle.
#[derive(Debug)]
pub struct FuseMount;

impl FuseMount {
    pub fn mount(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
    ) -> Result<MountHandle> {
        Self::mount_with(garden_root, state_root, session, sink, None)
    }

    /// Like [`Self::mount`] but accepts an optional [`SealedQuery`] adapter
    /// — when present, reads of sealed paths return the
    /// `[sealed:<path>]\n` placeholder instead of decrypted Layer A
    /// bytes. M2b daemons call this; M2a callers can keep using
    /// [`Self::mount`].
    pub fn mount_with(
        garden_root: &Path,
        state_root: &Path,
        session: Arc<VaultSession>,
        sink: Arc<dyn DirtyEventSink>,
        sealed: Option<Arc<dyn SealedQuery>>,
    ) -> Result<MountHandle> {
        let paths = StorePaths::with_state_root(garden_root, state_root);
        let db = Db::open(&paths)?;
        let objects = ObjectStore::new(paths.clone());

        let tip = db.try_get_ref(softfig_core::TIP_REF)?;
        let view = match tip {
            Some(h) => {
                let row = db.get_commit(&h)?;
                TreeView::build(&db, &row.root_tree)?
            }
            None => TreeView::empty(),
        };

        let mut inodes = InodeMap::new();
        for p in view.paths().map(|p| p.to_path_buf()).collect::<Vec<_>>() {
            inodes.intern(&p);
        }

        let state = Arc::new(SharedState {
            db: Mutex::new(db),
            objects,
            session,
            inner: Mutex::new(Inner {
                inodes,
                tip,
                view,
                overlay: Overlay::new(),
            }),
            sink,
            sealed,
            redacted_cache: Mutex::new(HashMap::new()),
        });

        let fs = FuseFs {
            state: state.clone(),
        };
        let opts = vec![
            fuser::MountOption::FSName("softfig".into()),
            fuser::MountOption::Subtype("softfig".into()),
            fuser::MountOption::DefaultPermissions,
        ];
        // Deliberately NOT `AutoUnmount`. fuser implicitly appends
        // `allow_other` whenever AutoUnmount is set (see fuser
        // `Session::new`), and `fusermount3` rejects `allow_other` unless
        // `user_allow_other` is enabled in /etc/fuse.conf — which surfaces
        // as an opaque `mount: Operation not permitted (EPERM)`. We never
        // want `allow_other` regardless: the decrypted garden must stay
        // readable only by the owning uid, never other users or root.
        //
        // The daemon already unmounts explicitly on every clean path
        // (entry to `Stopping`, `migrate_finalize`) via
        // `MountHandle::unmount`, so AutoUnmount only ever covered an
        // abnormal daemon death (SIGKILL/OOM/panic) leaving a dead mount.
        // `clear_stale_mount` reclaims that on the next mount instead, so
        // a crashed-then-restarted daemon self-heals without `allow_other`.
        clear_stale_mount(garden_root);
        let bg = fuser::spawn_mount2(fs, garden_root, &opts)?;

        Ok(MountHandle {
            background: Mutex::new(Some(bg)),
            state,
            mount_point: garden_root.to_path_buf(),
        })
    }

    /// Convenience for the daemon: register `MountHandle::on_tip_changed`
    /// as the repo's tip-changed callback. The closure captures a
    /// `Weak<SharedState>` so dropping the handle doesn't keep the FS
    /// state alive past unmount.
    pub fn install_tip_callback(repo: &mut Repo, handle: &MountHandle) {
        let state = Arc::downgrade(&handle.state);
        repo.set_tip_changed_callback(move |_hash: &Hash| {
            if let Some(s) = state.upgrade() {
                s.rotate_tip();
            }
        });
    }
}

struct FuseFs {
    state: Arc<SharedState>,
}

impl Filesystem for FuseFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.attr_for_child(parent, name) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self.attr_for_inode(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        match self.read_bytes(&path) {
            Ok(bytes) => {
                let start = offset.max(0) as usize;
                if start >= bytes.len() {
                    reply.data(&[]);
                    return;
                }
                let end = (start + size as usize).min(bytes.len());
                reply.data(&bytes[start..end]);
            }
            Err(_) => reply.error(libc::EIO),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (
                self.parent_inode(&path),
                FileType::Directory,
                "..".to_string(),
            ),
        ];
        for (child_path, kind) in self.list_children(&path) {
            let name = child_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string());
            let Some(name) = name else { continue };
            let child_inode = {
                let mut inner = self.state.inner.lock().unwrap();
                inner.inodes.intern(&child_path)
            };
            entries.push((child_inode, kind, name));
        }
        for (i, (inode, ftype, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(inode, (i + 1) as i64, ftype, name) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn open(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_file(path.clone(), Vec::new(), mode);
            inner.inodes.intern(&path)
        };
        let rel = path_to_repo_rel(&path);
        self.state.sink.created(&rel);
        self.state.sink.nudge();
        let attr = self
            .attr_for_inode(ino)
            .expect("just-created inode has attrs");
        reply.created(&TTL, &attr, 0, 0, 0);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let bytes = match self.read_bytes(&path) {
            Ok(b) => b,
            Err(_) => return reply.error(libc::EIO),
        };
        let mode = self.mode_of(ino).unwrap_or(0o100644);
        let start = offset.max(0) as usize;
        let end = start + data.len();
        let mut buf = bytes;
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[start..end].copy_from_slice(data);
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_file(path.clone(), buf, mode);
        }
        let rel = path_to_repo_rel(&path);
        self.state.sink.modified(&rel);
        self.state.sink.nudge();
        reply.written(data.len() as u32);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.insert_dir(path.clone(), mode);
            inner.inodes.intern(&path)
        };
        // mkdir alone doesn't create a commit-worthy event (empty dirs
        // aren't versioned without a `.keep` file); only nudge the
        // sink so it knows we're alive.
        self.state.sink.nudge();
        let attr = FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now(),
            mtime: now(),
            ctime: now(),
            crtime: now(),
            kind: FileType::Directory,
            perm: 0o755,
            nlink: 2,
            uid: *OWNER_UID,
            gid: *OWNER_GID,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        if self.path_kind(&path) != Some(EntryKind::Blob) {
            return reply.error(libc::ENOENT);
        }
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.mark_removed(path.clone());
            inner.inodes.forget(&path);
        }
        let rel = path_to_repo_rel(&path);
        self.state.sink.removed(&rel);
        self.state.sink.nudge();
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let Some(name_str) = name.to_str() else {
            return reply.error(libc::EINVAL);
        };
        let path = parent_path.join(name_str);
        if self.path_kind(&path) != Some(EntryKind::Dir) {
            return reply.error(libc::ENOENT);
        }
        // Recursive rmdir not supported (POSIX rmdir requires empty);
        // assume empty per kernel ABI.
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.mark_removed(path.clone());
            inner.inodes.forget(&path);
        }
        self.state.sink.nudge();
        reply.ok();
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let from_parent = match self.path_of(parent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let to_parent = match self.path_of(newparent) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        let (Some(n1), Some(n2)) = (name.to_str(), newname.to_str()) else {
            return reply.error(libc::EINVAL);
        };
        let from = from_parent.join(n1);
        let to = to_parent.join(n2);
        if self.path_kind(&from).is_none() {
            return reply.error(libc::ENOENT);
        }
        // Materialize the source bytes so the rename survives the
        // overlay-clears-on-commit semantics.
        let bytes = self.read_bytes(&from).unwrap_or_default();
        let mode = self.mode_of_path(&from).unwrap_or(0o100644);
        {
            let mut inner = self.state.inner.lock().unwrap();
            inner.overlay.mark_removed(from.clone());
            inner.overlay.insert_file(to.clone(), bytes, mode);
            inner.inodes.rename(&from, &to);
        }
        let from_rel = path_to_repo_rel(&from);
        let to_rel = path_to_repo_rel(&to);
        self.state.sink.renamed(&from_rel, &to_rel);
        self.state.sink.nudge();
        reply.ok();
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => return reply.error(libc::ENOENT),
        };
        // Truncate semantics: a setattr with size=0 + an O_TRUNC open
        // flag from the editor.
        if let Some(new_size) = size {
            let mut bytes = self.read_bytes(&path).unwrap_or_default();
            bytes.resize(new_size as usize, 0);
            let cur_mode = self.mode_of(ino).unwrap_or(0o100644);
            let next_mode = mode.unwrap_or(cur_mode);
            {
                let mut inner = self.state.inner.lock().unwrap();
                inner.overlay.insert_file(path.clone(), bytes, next_mode);
            }
            let rel = path_to_repo_rel(&path);
            self.state.sink.modified(&rel);
            self.state.sink.nudge();
        } else if let Some(new_mode) = mode {
            let bytes = self.read_bytes(&path).unwrap_or_default();
            {
                let mut inner = self.state.inner.lock().unwrap();
                inner.overlay.insert_file(path.clone(), bytes, new_mode);
            }
            let rel = path_to_repo_rel(&path);
            self.state.sink.modified(&rel);
            self.state.sink.nudge();
        }
        match self.attr_for_inode(ino) {
            Some(a) => reply.attr(&TTL, &a),
            None => reply.error(libc::ENOENT),
        }
    }
}

// ---- internal helpers ----

impl FuseFs {
    fn path_of(&self, ino: u64) -> Option<PathBuf> {
        let inner = self.state.inner.lock().unwrap();
        inner.inodes.path_of(ino).map(|p| p.to_path_buf())
    }

    fn parent_inode(&self, path: &Path) -> u64 {
        if path.as_os_str().is_empty() {
            return ROOT_INODE;
        }
        let parent = path.parent().unwrap_or(Path::new(""));
        let mut inner = self.state.inner.lock().unwrap();
        inner.inodes.intern(parent)
    }

    fn attr_for_child(&self, parent: u64, name: &OsStr) -> Option<FileAttr> {
        let parent_path = self.path_of(parent)?;
        let name_str = name.to_str()?;
        let path = parent_path.join(name_str);
        let ino = {
            let mut inner = self.state.inner.lock().unwrap();
            inner.inodes.intern(&path)
        };
        self.attr_for_path(&path, ino)
    }

    fn attr_for_inode(&self, ino: u64) -> Option<FileAttr> {
        if ino == ROOT_INODE {
            return Some(self.dir_attr(ROOT_INODE, 0o755));
        }
        let path = self.path_of(ino)?;
        self.attr_for_path(&path, ino)
    }

    fn attr_for_path(&self, path: &Path, ino: u64) -> Option<FileAttr> {
        let inner = self.state.inner.lock().unwrap();
        // Overlay takes precedence.
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::Removed => None,
                OverlayEntry::File { content, mode } => Some(FileAttr {
                    ino,
                    size: content.len() as u64,
                    blocks: (content.len() as u64).div_ceil(BLOCK_SIZE as u64),
                    atime: now(),
                    mtime: now(),
                    ctime: now(),
                    crtime: now(),
                    kind: FileType::RegularFile,
                    perm: (mode & 0o7777) as u16,
                    nlink: 1,
                    uid: *OWNER_UID,
                    gid: *OWNER_GID,
                    rdev: 0,
                    blksize: BLOCK_SIZE,
                    flags: 0,
                }),
                OverlayEntry::Dir { mode } => Some(self.dir_attr(ino, *mode)),
            };
        }
        // Fall back to tip view.
        let entry = inner.view.get(path)?.clone();
        drop(inner);
        Some(match entry.kind {
            EntryKind::Blob => {
                // We don't know the plaintext size without decrypting; do it
                // here (cached by the kernel via TTL).
                let bytes = self.read_bytes(path).unwrap_or_default();
                FileAttr {
                    ino,
                    size: bytes.len() as u64,
                    blocks: (bytes.len() as u64).div_ceil(BLOCK_SIZE as u64),
                    atime: now(),
                    mtime: now(),
                    ctime: now(),
                    crtime: now(),
                    kind: FileType::RegularFile,
                    perm: (entry.mode & 0o7777) as u16,
                    nlink: 1,
                    uid: *OWNER_UID,
                    gid: *OWNER_GID,
                    rdev: 0,
                    blksize: BLOCK_SIZE,
                    flags: 0,
                }
            }
            EntryKind::Dir => self.dir_attr(ino, entry.mode),
        })
    }

    fn dir_attr(&self, ino: u64, mode: u32) -> FileAttr {
        FileAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: now(),
            mtime: now(),
            ctime: now(),
            crtime: now(),
            kind: FileType::Directory,
            perm: (mode & 0o7777) as u16,
            nlink: 2,
            uid: *OWNER_UID,
            gid: *OWNER_GID,
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        // Overlay precedence (in-flight write, not yet committed; if the
        // overlay holds plaintext that just got dropped by a write to a
        // sealed-matching path, we surface the placeholder so a reader
        // never sees the live plaintext after a `nudge` lands a flush).
        {
            let inner = self.state.inner.lock().unwrap();
            if let Some(entry) = inner.overlay.get(path) {
                return match entry {
                    OverlayEntry::File { content, .. } => {
                        if self.is_sealed_path(path) {
                            Ok(sealed_placeholder(path))
                        } else {
                            // Overlay bytes are pre-commit plaintext —
                            // run them through the M2c region redactor
                            // too so live in-flight reads of an
                            // unsaved edit don't leak the freshly-typed
                            // plaintext body. Not cached: overlay
                            // content is mutable until the commit lands.
                            Ok(self.apply_redactions(path, content.clone()))
                        }
                    }
                    _ => Ok(Vec::new()),
                };
            }
        }
        // Tip view: decrypt the blob (unless this path is sealed).
        if self.is_sealed_path(path) {
            return Ok(sealed_placeholder(path));
        }
        // M2c — cache the post-`redact_regions` bytes per path. Cache
        // is broadcast-invalidated on every `tip_changed`.
        if let Some(cached) = self.state.redacted_cache.lock().unwrap().get(path).cloned() {
            return Ok(cached);
        }
        let inner = self.state.inner.lock().unwrap();
        let entry = match inner.view.get(path) {
            Some(e) if e.kind == EntryKind::Blob => e.clone(),
            _ => return Ok(Vec::new()),
        };
        drop(inner);
        let cipher = self.state.objects.get(&entry.target)?;
        let plain = self.state.session.decrypt_blob(&cipher)?;
        let redacted = self.apply_redactions(path, plain);
        self.state
            .redacted_cache
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), redacted.clone());
        Ok(redacted)
    }

    /// M2c — funnel post-Layer-A plaintext through the daemon's
    /// region redactor (no-op for `None` sealed adapter or paths with
    /// no `<vault>` regions, by virtue of the default-impl identity).
    fn apply_redactions(&self, path: &Path, content: Vec<u8>) -> Vec<u8> {
        let Some(q) = self.state.sealed.as_ref() else {
            return content;
        };
        q.redact_regions(&path_to_repo_rel(path), content)
    }

    fn is_sealed_path(&self, path: &Path) -> bool {
        let Some(q) = self.state.sealed.as_ref() else {
            return false;
        };
        q.is_sealed(&path_to_repo_rel(path))
    }

    fn path_kind(&self, path: &Path) -> Option<EntryKind> {
        let inner = self.state.inner.lock().unwrap();
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::File { .. } => Some(EntryKind::Blob),
                OverlayEntry::Dir { .. } => Some(EntryKind::Dir),
                OverlayEntry::Removed => None,
            };
        }
        inner.view.get(path).map(|e| e.kind)
    }

    fn mode_of(&self, ino: u64) -> Option<u32> {
        let path = self.path_of(ino)?;
        self.mode_of_path(&path)
    }

    fn mode_of_path(&self, path: &Path) -> Option<u32> {
        let inner = self.state.inner.lock().unwrap();
        if let Some(entry) = inner.overlay.get(path) {
            return match entry {
                OverlayEntry::File { mode, .. } => Some(*mode),
                OverlayEntry::Dir { mode } => Some(*mode),
                OverlayEntry::Removed => None,
            };
        }
        inner.view.get(path).map(|e| e.mode)
    }

    fn list_children(&self, dir: &Path) -> Vec<(PathBuf, FileType)> {
        let inner = self.state.inner.lock().unwrap();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        // Tip view first.
        for (child_path, entry) in inner.view.children(dir) {
            seen.insert(child_path.to_path_buf());
            // Hidden by overlay removal?
            if matches!(inner.overlay.get(child_path), Some(OverlayEntry::Removed)) {
                continue;
            }
            // Overridden by overlay? (We'll surface the overlay copy
            // below; skip the tip version here to avoid duplicates.)
            if inner.overlay.get(child_path).is_some() {
                continue;
            }
            let ftype = match entry.kind {
                EntryKind::Blob => FileType::RegularFile,
                EntryKind::Dir => FileType::Directory,
            };
            out.push((child_path.to_path_buf(), ftype));
        }
        // Overlay entries (new files + new dirs + overrides).
        for (path, entry) in inner.overlay.iter() {
            if path.parent() != Some(dir) {
                continue;
            }
            if matches!(entry, OverlayEntry::Removed) {
                continue;
            }
            let p = path.to_path_buf();
            if seen.insert(p.clone()) || !seen.contains(&p) {
                // First-time addition.
            }
            let ftype = match entry {
                OverlayEntry::File { .. } => FileType::RegularFile,
                OverlayEntry::Dir { .. } => FileType::Directory,
                OverlayEntry::Removed => unreachable!(),
            };
            // Deduplicate against any tip entry we already pushed.
            if !out.iter().any(|(q, _)| q == &p) {
                out.push((p, ftype));
            }
        }
        out
    }
}

fn now() -> SystemTime {
    SystemTime::now()
}

fn path_to_repo_rel(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Forward-compatible with M2c's inline `<vault id="...">[sealed]</vault>`
/// placeholder mechanism: same shape — a short ASCII marker computed on
/// each read, never persisted — at a different scope (whole-file here,
/// region in M2c).
fn sealed_placeholder(path: &Path) -> Vec<u8> {
    format!("[sealed:{}]\n", path_to_repo_rel(path)).into_bytes()
}

#[allow(dead_code)]
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Reclaim a stale FUSE mount left at `mount_point` by a previously
/// crashed daemon (one that died without running `MountHandle::unmount`).
///
/// Without `AutoUnmount`, the kernel does not auto-reap such a mount; it
/// lingers as a dead endpoint (`ls` → `ENOTCONN`) and a fresh
/// `spawn_mount2` would stack on top of the corpse. We detect an existing
/// `fuse*` mount exactly at `mount_point` and lazily unmount it via the
/// setuid `fusermount3` helper (`-z` so a busy/dead mount still detaches).
/// No-op when nothing is mounted there — the common case.
fn clear_stale_mount(mount_point: &Path) {
    if !is_fuse_mount(mount_point) {
        return;
    }
    // `fusermount3 -u -q -z` is the same unmount path fuser itself uses;
    // `-z` (lazy) handles the dead/busy endpoint. Failure is non-fatal:
    // the subsequent mount will surface any real problem.
    let _ = std::process::Command::new("fusermount3")
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(mount_point)
        .status();
}

/// True if `/proc/self/mountinfo` shows a `fuse*` filesystem mounted
/// exactly at `target`. Garden roots are plain ASCII paths with no spaces
/// (a garden house rule), so the kernel's octal-escaped mountinfo field
/// compares verbatim.
fn is_fuse_mount(target: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let target = target.to_string_lossy();
    for line in content.lines() {
        // mountinfo: `… root mount_point opts … - fstype source superopts`.
        // Field index 4 (0-based) before " - " is the mount point.
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let mount_point = pre.split_whitespace().nth(4);
        let fstype = post.split_whitespace().next().unwrap_or("");
        if mount_point == Some(target.as_ref()) && fstype.starts_with("fuse") {
            return true;
        }
    }
    false
}
