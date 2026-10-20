//! The **repo an item's work lands in**, and a cheap read of how far that repo
//! has moved — the one lookup growlightd's spin guard (task 069) and the boot-time
//! dirty-tree guard (task 064) share, so the two can't disagree about which repo
//! an item lives in.
//!
//! The lookup order is fixed:
//!
//! 1. the item doc's own `> Worktree:` blockquote line ([`worktree_field`]) —
//!    a milestone's `CLAUDE.md` or a task doc;
//! 2. the queue registry's `repo` column (the caller reads it);
//! 3. none.
//!
//! [`resolve_repo`] takes the first one *present*. A present value that is not a
//! local absolute path after `~` expansion — a relative path, or a remote
//! `host:/path` like roadeye's — resolves to `None` rather than falling through:
//! the doc named a repo this machine can't probe, and the registry's row is not a
//! better guess at it. `None` means "no repo signal", never an error.
//!
//! [`probe`] reads a repo through `git` without taking `index.lock`
//! (`--no-optional-locks`), so it never races the member's own git running in the
//! same worktree. What it reports is deliberately coarse: `HEAD`, how many paths
//! are dirty, the newest dirty mtime, and a fingerprint of the dirty set's
//! *content* — enough to tell "this session moved the repo" from "this session
//! didn't", nothing more. Ignored paths (`target/`) never reach it, by
//! construction of `git status`.
//!
//! Every phase is bounded so a probe can fail but never stall its caller (the
//! growlightd drive loop runs it on its one thread): each `git` child is killed
//! after [`GIT_TIMEOUT`], and the in-process hashing phase runs on its own
//! thread under [`HASH_TIMEOUT`] — a metadata or read syscall on a hung mount
//! abandons that thread and fails the probe. Non-regular files are never
//! opened at all ([`hash_content`]): `open(2)` on a FIFO blocks until a writer
//! appears.

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

/// How much of one dirty file's content goes into the fingerprint. The file's
/// length is hashed too, so an edit past the cap still moves the fingerprint
/// unless it keeps the length — a churning multi-MiB file is not the case this
/// guards.
const CONTENT_CAP: u64 = 4 * 1024 * 1024;

/// How long one `git` call may run before it is killed. A probe runs once per
/// member session, off the hot path, but it must never wedge the supervisor.
const GIT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the in-process hashing phase (metadata + content reads over the
/// dirty list) may take before the probe fails. The `git` children have their
/// own [`GIT_TIMEOUT`]; this one bounds the caller-side work that follows them,
/// which runs on a dedicated thread — a read on a hung mount cannot be
/// interrupted, so on timeout that thread is abandoned and the probe fails
/// instead of stalling the drive loop that calls [`probe`].
const HASH_TIMEOUT: Duration = Duration::from_secs(10);

/// The value of the doc's first `> Worktree:` blockquote line outside fenced
/// code, trimmed; `None` when there is none or it is empty.
///
/// Read through the shared scanner ([`crate::item_meta::field`]) every
/// item-doc metadata reader uses: the key is case-insensitive, a ```` ``` ```` /
/// `~~~` fence toggles, and prose or inline code that merely mentions the
/// marker doesn't count.
pub fn worktree_field(doc: &str) -> Option<&str> {
    crate::item_meta::field(doc, crate::item_meta::WORKTREE).filter(|v| !v.is_empty())
}

/// The local repo path for an item: `worktree` (the doc's `> Worktree:`) if
/// present, else `registry` (the queue registry's `repo` cell), else `None`.
///
/// A leading `~` / `~/` expands against `home`. A value wrapped in backticks is
/// unwrapped. Anything that is not absolute after that — relative, `~user`, a
/// remote `host:/path`, `~` with no `home` — gives `None` (see the module doc on
/// why a present-but-unusable worktree does not fall through to the registry).
pub fn resolve_repo(
    worktree: Option<&str>,
    registry: Option<&str>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    fn present(v: Option<&str>) -> Option<&str> {
        v.map(|v| v.trim().trim_matches('`').trim()).filter(|v| !v.is_empty())
    }
    let value = present(worktree).or_else(|| present(registry))?;
    let path = if value == "~" {
        home?.to_path_buf()
    } else if let Some(rest) = value.strip_prefix("~/") {
        home?.join(rest)
    } else {
        PathBuf::from(value)
    };
    path.is_absolute().then_some(path)
}

/// One read of a repo: where `HEAD` is and what the dirty tree looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    /// `HEAD`'s commit hash; `None` on an unborn branch.
    pub head: Option<String>,
    /// How many paths `git status` reports (tracked changes + untracked files).
    pub dirty: usize,
    /// The newest mtime among the dirty paths still on disk.
    pub newest_dirty_mtime: Option<SystemTime>,
    /// A hash over every dirty entry's status, path and content. Equal for two
    /// reads of the same dirty tree; re-writing a file with identical bytes
    /// leaves it alone.
    pub fingerprint: u64,
}

impl RepoState {
    /// What "the repo moved" compares: `HEAD` and the dirty fingerprint. The
    /// mtime is left out on purpose — a touch that changes no byte is not work.
    pub fn progress_key(&self) -> (Option<String>, u64) {
        (self.head.clone(), self.fingerprint)
    }
}

/// Read `repo`'s [`RepoState`] through `git`. `Err` when `repo` is not a git
/// repo, `git` can't be run, or a call outlives its timeout.
pub fn probe(repo: &Path) -> Result<RepoState, String> {
    // Status first: it is the call that fails outright on a non-repo, which keeps
    // rev-parse's exit 1 unambiguous ("unborn HEAD", not "no repo").
    let (status, out) = git(repo, &["status", "--porcelain=v1", "-z", "--untracked-files=all"])?;
    if !status.success() {
        return Err(format!("git status in {}: {status}", repo.display()));
    }
    let (dirty, newest_dirty_mtime, fingerprint) = hash_dirty_entries(repo, &out)?;
    let (status, out) = git(repo, &["rev-parse", "--verify", "-q", "HEAD"])?;
    let head = match status.code() {
        Some(0) => Some(String::from_utf8_lossy(&out).trim().to_string()),
        Some(1) => None,
        _ => return Err(format!("git rev-parse HEAD in {}: {status}", repo.display())),
    };
    Ok(RepoState { head, dirty, newest_dirty_mtime, fingerprint })
}

/// Hash `git status -z` output into `(dirty, newest_dirty_mtime, fingerprint)`.
///
/// The whole phase runs on a worker thread the caller joins under
/// [`HASH_TIMEOUT`]: a single hung metadata or read syscall (a dead NFS mount)
/// can't be interrupted, so on timeout the worker is abandoned and the probe
/// fails — the drive-loop thread that calls [`probe`] is never stalled. A
/// per-entry deadline check inside the worker ends the phase early (as an
/// error) when a merely slow tree would otherwise burn the full budget.
fn hash_dirty_entries(
    repo: &Path,
    out: &[u8],
) -> Result<(usize, Option<SystemTime>, u64), String> {
    let out = out.to_vec();
    let repo = repo.to_path_buf();
    let label = repo.display().to_string();
    let (tx, rx) = mpsc::channel();
    let inner_label = label.clone();
    thread::spawn(move || {
        let deadline = Instant::now() + HASH_TIMEOUT;
        let mut hasher = DefaultHasher::new();
        let mut dirty = 0;
        let mut newest_dirty_mtime = None;
        let mut fields = out.split(|&b| b == 0).filter(|f| !f.is_empty());
        while let Some(entry) = fields.next() {
            if Instant::now() >= deadline {
                let _ = tx.send(Err(format!("hash phase in {inner_label}: timed out")));
                return;
            }
            if entry.len() < 4 || entry[2] != b' ' {
                let _ = tx.send(Err(format!("git status in {inner_label}: unparsable entry")));
                return;
            }
            let (xy, path) = (&entry[..2], &entry[3..]);
            // A rename or copy carries its source path as one more field; it names
            // the old location, so it is hashed but never read.
            if xy.iter().any(|&c| c == b'R' || c == b'C') {
                fields.next().hash(&mut hasher);
            }
            dirty += 1;
            xy.hash(&mut hasher);
            path.hash(&mut hasher);
            let full = repo.join(String::from_utf8_lossy(path).as_ref());
            match fs::symlink_metadata(&full) {
                Ok(meta) => {
                    if let Ok(mtime) = meta.modified() {
                        newest_dirty_mtime = newest_dirty_mtime.max(Some(mtime));
                    }
                    hash_content(&full, &meta, &mut hasher);
                }
                Err(_) => b"\0missing".hash(&mut hasher),
            }
        }
        let _ = tx.send(Ok((dirty, newest_dirty_mtime, hasher.finish())));
    });
    match rx.recv_timeout(HASH_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!("hash phase in {label}: timed out")),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(format!("hash phase in {label}: panicked")),
    }
}

/// Hash a dirty path's content: a symlink's target, else a regular file's
/// length plus its first [`CONTENT_CAP`] bytes. A path that can't be read (a
/// permission error) hashes a marker instead. Anything else — a FIFO, socket,
/// device, or directory — contributes nothing: opening it could block the
/// caller forever (open(2) on a FIFO waits for a writer), and its existence
/// already counts through git's own status entry.
fn hash_content(full: &Path, meta: &fs::Metadata, hasher: &mut DefaultHasher) {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        match fs::read_link(full) {
            Ok(target) => target.hash(hasher),
            Err(_) => b"\0unreadable".hash(hasher),
        }
        return;
    }
    if !file_type.is_file() {
        return;
    }
    let mut buf = Vec::new();
    let read = fs::File::open(full).and_then(|f| f.take(CONTENT_CAP).read_to_end(&mut buf));
    match read {
        Ok(_) => {
            meta.len().hash(hasher);
            buf.hash(hasher);
        }
        Err(_) => b"\0unreadable".hash(hasher),
    }
}

/// Run `git --no-optional-locks -C <repo> <args>` and return its exit status and
/// stdout, killing it after [`GIT_TIMEOUT`]. stdout is drained on its own thread
/// so a large dirty tree can't fill the pipe and stall the child.
fn git(repo: &Path, args: &[&str]) -> Result<(ExitStatus, Vec<u8>), String> {
    let mut child = Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn git: {e}"))?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).map(|_| out)
    });
    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!("git {} in {}: timed out", args[0], repo.display()));
            }
            Err(e) => return Err(format!("wait on git: {e}")),
        }
    };
    let out = reader
        .join()
        .map_err(|_| "git stdout reader panicked".to_string())?
        .map_err(|e| format!("read git stdout: {e}"))?;
    Ok((status, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worktree_field_is_the_first_blockquote_line_outside_a_fence() {
        let doc = "# folder-grants\n\n> Last reviewed: 2026-10-17\n> Worktree: ~/projects/x\n";
        assert_eq!(worktree_field(doc), Some("~/projects/x"));
        assert_eq!(worktree_field("> worktree:   /a  \n"), Some("/a"), "key is case-insensitive");
        assert_eq!(worktree_field("> Worktree: /a\n> Worktree: /b\n"), Some("/a"), "first wins");
        assert_eq!(worktree_field("```\n> Worktree: /a\n```\n"), None, "a fenced example");
        assert_eq!(worktree_field("~~~\n> Worktree: /a\n~~~\n> Worktree: /b\n"), Some("/b"));
        assert_eq!(worktree_field("Worktree: /a in prose\n`> Worktree: /b`\n"), None);
        assert_eq!(worktree_field("> Worktree:\n"), None, "empty is absent");
    }

    #[test]
    fn resolve_repo_takes_the_first_present_source() {
        let home = Path::new("/home/u");
        let r = |w, g| resolve_repo(w, g, Some(home));
        assert_eq!(r(Some("/w"), Some("/g")), Some(PathBuf::from("/w")), "worktree beats registry");
        assert_eq!(r(None, Some("/g")), Some(PathBuf::from("/g")));
        assert_eq!(r(Some("  "), Some("/g")), Some(PathBuf::from("/g")), "blank is absent");
        assert_eq!(r(None, None), None);
        assert_eq!(r(Some("~/p/x"), None), Some(PathBuf::from("/home/u/p/x")));
        assert_eq!(r(Some("~"), None), Some(PathBuf::from("/home/u")));
        assert_eq!(r(Some("`/w`"), None), Some(PathBuf::from("/w")), "backticks unwrap");
        assert_eq!(resolve_repo(Some("~/p"), None, None), None, "no home to expand against");
    }

    #[test]
    fn resolve_repo_refuses_what_it_cannot_probe_locally() {
        let home = Some(Path::new("/home/u"));
        let remote = "otg-travel:/home/sshukv/projects/roadeye (REMOTE — ssh otg-travel)";
        assert_eq!(resolve_repo(None, Some(remote), home), None);
        assert_eq!(resolve_repo(Some("projects/x"), None, home), None, "relative");
        assert_eq!(resolve_repo(Some("~bob/x"), None, home), None, "~user is not expanded");
        // A present-but-unusable worktree does not fall through to the registry.
        assert_eq!(resolve_repo(Some("host:/x"), Some("/g"), home), None);
    }

    fn sh_git(repo: &Path, args: &[&str]) {
        git_with_stdin(repo, args, Stdio::null());
    }

    #[test]
    fn probe_tracks_head_and_the_dirty_trees_content() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        sh_git(repo, &["init", "-q"]);
        let unborn = probe(repo).unwrap();
        assert_eq!((unborn.head.as_deref(), unborn.dirty), (None, 0));

        fs::write(repo.join(".gitignore"), "target/\n").unwrap();
        fs::write(repo.join("a.txt"), "one\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);
        let clean = probe(repo).unwrap();
        assert!(clean.head.is_some());
        assert_eq!((clean.dirty, clean.newest_dirty_mtime), (0, None));

        fs::create_dir(repo.join("target")).unwrap();
        fs::write(repo.join("target/build.o"), "junk").unwrap();
        assert_eq!(probe(repo).unwrap(), clean, "an ignored file is not dirt");

        fs::write(repo.join("a.txt"), "two\n").unwrap();
        let edited = probe(repo).unwrap();
        assert_eq!(edited.dirty, 1);
        assert!(edited.newest_dirty_mtime.is_some());
        assert_eq!(edited.head, clean.head);
        assert_ne!(edited.progress_key(), clean.progress_key(), "an edit moves the key");

        fs::write(repo.join("a.txt"), "two\n").unwrap();
        assert_eq!(probe(repo).unwrap().progress_key(), edited.progress_key(), "same bytes");

        fs::write(repo.join("a.txt"), "three\n").unwrap();
        let reedited = probe(repo).unwrap();
        assert_eq!(reedited.dirty, 1);
        assert_ne!(reedited.fingerprint, edited.fingerprint, "same path, new content");

        fs::write(repo.join("new.txt"), "n\n").unwrap();
        assert_eq!(probe(repo).unwrap().dirty, 2, "untracked files count");

        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "work"]);
        let committed = probe(repo).unwrap();
        assert_eq!(committed.dirty, 0);
        assert_ne!(committed.head, clean.head, "a commit moves HEAD");
    }

    #[test]
    fn probe_reads_a_rename_entry_without_losing_its_place() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        sh_git(repo, &["init", "-q"]);
        fs::write(repo.join("old.txt"), "body\n").unwrap();
        fs::write(repo.join("z.txt"), "z\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);
        sh_git(repo, &["mv", "old.txt", "new.txt"]);
        fs::write(repo.join("z.txt"), "zz\n").unwrap();
        // `R  new.txt\0old.txt\0 M z.txt\0`: the orig-path field must not be
        // read as an entry of its own.
        assert_eq!(probe(repo).unwrap().dirty, 2);
    }

    #[test]
    fn probe_of_a_non_repo_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe(dir.path()).is_err());
        assert!(probe(&dir.path().join("absent")).is_err());
    }

    /// A tracked FIFO in the dirty tree must never be opened: open(2) on a FIFO
    /// blocks until a writer appears, so the old probe would hang forever right
    /// here — the exact hang report 029 is about. The FIFO is tracked without
    /// opening it (`git add` on a FIFO would block too; modern git omits
    /// untracked special files from `status`, so only the tracked form reaches
    /// the probe). The probe completes, counts the FIFO as dirt, and hashes
    /// nothing for it.
    #[cfg(unix)]
    #[test]
    fn probe_skips_a_tracked_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        sh_git(repo, &["init", "-q"]);
        fs::write(repo.join("a.txt"), "base\n").unwrap();
        sh_git(repo, &["add", "."]);
        sh_git(repo, &["commit", "-q", "-m", "base"]);

        // Write the empty blob into the odb and insert the index entry by hand:
        // cacheinfo never touches the worktree file.
        let fifo = repo.join("pipe");
        mkfifo(&fifo);
        git_with_stdin(repo, &["hash-object", "-w", "--stdin"], Stdio::null());
        sh_git(
            repo,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                "100644,e69de29bb2d1d6434b8b29ae775ad8c2e48c5391,pipe",
            ],
        );
        sh_git(repo, &["commit", "-q", "-m", "track the fifo"]);

        let state = probe(repo).expect("a fifo in the dirty tree is not an error");
        assert_eq!(state.dirty, 1, "the fifo still counts as dirt");
        // Its (unreadable) content is not part of the fingerprint: bumping the
        // fifo's mtime moves the mtime and nothing else.
        touch(&fifo);
        let again = probe(repo).expect("a second probe is not an error");
        assert_eq!(again.fingerprint, state.fingerprint, "a fifo contributes no hash");
    }

    /// The unit behind the probe test: `hash_content` contributes nothing for a
    /// non-regular file — the hasher is untouched, byte for byte. With the old
    /// code this test would block forever inside `File::open` on the FIFO.
    #[cfg(unix)]
    #[test]
    fn hash_content_contributes_nothing_for_a_fifo_or_socket() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        mkfifo(&fifo);
        let sock = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let empty = DefaultHasher::new().finish();
        for path in [&fifo, &sock] {
            let meta = fs::symlink_metadata(path).unwrap();
            let mut hasher = DefaultHasher::new();
            hash_content(path, &meta, &mut hasher);
            assert_eq!(hasher.finish(), empty, "{} contributes no hash", path.display());
        }
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let ok = Command::new("mkfifo")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run mkfifo")
            .success();
        assert!(ok, "mkfifo {}", path.display());
    }

    #[cfg(unix)]
    fn touch(path: &Path) {
        let ok = Command::new("touch")
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run touch")
            .success();
        assert!(ok, "touch {}", path.display());
    }

    fn git_with_stdin(repo: &Path, args: &[&str], stdin: Stdio) {
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git")
            .success();
        assert!(ok, "git {args:?}");
    }
}
