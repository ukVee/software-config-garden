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

use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
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

/// The value of the doc's first `> Worktree:` blockquote line outside fenced
/// code, trimmed; `None` when there is none or it is empty.
///
/// The scan is the one 068's `> Fleet:` marker uses: the key is
/// case-insensitive, a ```` ``` ```` / `~~~` fence toggles, and prose or inline
/// code that merely mentions the marker doesn't count.
pub fn worktree_field(doc: &str) -> Option<&str> {
    let mut fenced = false;
    for line in doc.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix('>') else {
            continue;
        };
        let Some((key, value)) = rest.trim().split_once(':') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("worktree") {
            let value = value.trim();
            return (!value.is_empty()).then_some(value);
        }
    }
    None
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
    let mut hasher = DefaultHasher::new();
    let mut dirty = 0;
    let mut newest_dirty_mtime = None;
    let mut fields = out.split(|&b| b == 0).filter(|f| !f.is_empty());
    while let Some(entry) = fields.next() {
        if entry.len() < 4 || entry[2] != b' ' {
            return Err(format!("git status in {}: unparsable entry", repo.display()));
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
    let (status, out) = git(repo, &["rev-parse", "--verify", "-q", "HEAD"])?;
    let head = match status.code() {
        Some(0) => Some(String::from_utf8_lossy(&out).trim().to_string()),
        Some(1) => None,
        _ => return Err(format!("git rev-parse HEAD in {}: {status}", repo.display())),
    };
    Ok(RepoState { head, dirty, newest_dirty_mtime, fingerprint: hasher.finish() })
}

/// Hash a dirty path's content: a symlink's target, else the file's length plus
/// its first [`CONTENT_CAP`] bytes. A path that can't be read (a directory, a
/// permission error) hashes a marker instead.
fn hash_content(full: &Path, meta: &fs::Metadata, hasher: &mut DefaultHasher) {
    if meta.file_type().is_symlink() {
        match fs::read_link(full) {
            Ok(target) => target.hash(hasher),
            Err(_) => b"\0unreadable".hash(hasher),
        }
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
        let ok = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run git")
            .success();
        assert!(ok, "git {args:?}");
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
}
