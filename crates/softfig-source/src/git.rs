//! Git implementation #1 of the source transfer (spec remote-runner §4.2–§4.4):
//! a temp-index snapshot on the requester, a `have/want` bundle stream, and a
//! hardened `fetch` + `read-tree`/`checkout-index` ingest/materialize on the
//! runner.
//!
//! Every runner-side invocation is a bare `git` child process carrying the
//! [`RUNNER_GIT_CONFIG`] hardening; the requester side runs `git` in the user's
//! own repo with no extra config. No git library: the snapshot must behave
//! exactly like `git add -A` (respecting `.gitignore` / gitattributes) and the
//! bundle must be a real `git bundle`, so we shell out to the real binary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{Error, Result};
use crate::source_id::SourceId;

/// Deterministic snapshot-commit identity (spec §4.2): author and committer are
/// both this name/email and the date is HEAD's committer date, so the same tree
/// on the same HEAD always yields the same commit.
pub const SNAPSHOT_AUTHOR_NAME: &str = "softfig-run";
pub const SNAPSHOT_AUTHOR_EMAIL: &str = "softfig-run@localhost";
pub const SNAPSHOT_MESSAGE: &str = "softfig-run snapshot";

/// How a snapshot treats gitlinks (submodules) in the tree (spec §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmodulePolicy {
    /// Refuse a tree containing gitlinks — v1 ships no submodule content.
    Refuse,
    /// Allow gitlinks (they materialize as empty directories on the runner).
    Ignore,
}

/// A git snapshot: the content-addressed source id (tree) plus the synthetic
/// commit that wraps it for transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub source_id: SourceId,
    /// The snapshot commit id, raw bytes (length per `source_id.format`).
    pub commit: Vec<u8>,
}

/// The tips a runner holds for a repo key (the `SourceHave` reply, spec §4.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HaveTips {
    /// Recent snapshot-tip commit ids (the `refs/softfig/snap/*` tips).
    pub tips: Vec<Vec<u8>>,
    /// Their first parents — the shared history the requester also has.
    pub commits: Vec<Vec<u8>>,
}

/// Upper bound on the tips a `SourceHave` reply carries (spec §4.3 "bounded").
pub const TIP_LIMIT: usize = 32;

/// Hardening config applied to **every** runner-side git invocation (spec
/// §4.4). `protocol.allow=never` forbids every transport and
/// `protocol.file.allow=always` re-allows only the local-file transport the
/// bundle fetch uses (a bundle is a local temp file — no network, no ssh, no
/// git://). `transfer.fsckObjects` rejects the malformed-object tricks git
/// knows about.
pub const RUNNER_GIT_CONFIG: &[(&str, &str)] = &[
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("protocol.allow", "never"),
    ("protocol.file.allow", "always"),
    ("transfer.fsckObjects", "true"),
    ("fetch.fsckObjects", "true"),
];

/// The runner-side snapshot ref for a source id (spec §4.3: the mirror fetches
/// the bundle into `refs/softfig/snap/<source_id>`).
pub fn snapshot_ref(source_id: &SourceId) -> String {
    format!("refs/softfig/snap/{}", source_id.hex())
}

// --- The git child-process primitive --------------------------------------

/// Run `git` with an optional `-C` working dir, `-c` config pairs, and extra
/// env vars. Returns raw stdout bytes; a non-zero exit is a [`Error::Git`].
fn run_git(
    dir: Option<&Path>,
    env: &[(&str, &str)],
    config: &[(&str, &str)],
    args: &[&str],
) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    if let Some(d) = dir {
        cmd.arg("-C").arg(d);
    }
    for (k, v) in config {
        cmd.arg("-c").arg(format!("{k}={v}"));
    }
    cmd.args(args);
    cmd.stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(Error::Git {
            cmd: format!("git {}", args.join(" ")),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(out.stdout)
}

/// Run `git` in `dir` (requester side — the user's own repo, no hardening).
fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = run_git(Some(dir), &[], &[], args)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Run `git` in `dir` with the runner hardening config (runner side).
fn git_runner(dir: &Path, args: &[&str]) -> Result<String> {
    let out = run_git(Some(dir), &[], RUNNER_GIT_CONFIG, args)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Whether the repo has a commit object named `hex` (`git cat-file -e`).
fn has_commit(repo: &Path, hex: &str) -> bool {
    run_git(Some(repo), &[], &[], &["cat-file", "-e", &format!("{hex}^{{commit}}")]).is_ok()
}

fn path_str<'a>(p: &'a Path, what: &'static str) -> Result<&'a str> {
    p.to_str()
        .ok_or_else(|| Error::Bundle(format!("{what} path is not valid UTF-8: {}", p.display())))
}

// --- Requester side --------------------------------------------------------

/// Snapshot a git worktree into an immutable tree + synthetic commit, without
/// touching the real index, refs or worktree (spec §4.2). Dirty tracked files
/// and untracked-but-not-ignored files are included; ignored files are not.
/// Works from a worktree of a bare-plus-worktrees repo (the temp index lives
/// beside the real one, which stays byte-identical).
pub fn snapshot_repo(repo: &Path, submodules: SubmodulePolicy) -> Result<Snapshot> {
    // Copy the real index to a temp file; `git add -A` then writes only the
    // temp copy, leaving the real index byte-identical.
    let git_dir = git(repo, &["rev-parse", "--absolute-git-dir"])?;
    let real_index = PathBuf::from(git_dir).join("index");
    let tmp_index = tempfile::NamedTempFile::new()?;
    if real_index.exists() {
        std::fs::copy(&real_index, tmp_index.path())?;
    }
    let index_path = path_str(tmp_index.path(), "temp index")?.to_string();

    // The env var GIT_INDEX_FILE routes add/write-tree/ls-files at the temp
    // index, so the real index is never written.
    let index_env: &[(&str, &str)] = &[("GIT_INDEX_FILE", index_path.as_str())];
    run_git(Some(repo), index_env, &[], &["add", "-A"])?;

    // Gitlinks are refused unless the profile ignores them (spec §4.2).
    if submodules == SubmodulePolicy::Refuse {
        let staged = String::from_utf8_lossy(&run_git(
            Some(repo),
            index_env,
            &[],
            &["ls-files", "--stage"],
        )?)
        .into_owned();
        if staged.lines().any(|l| l.starts_with("160000 ")) {
            return Err(Error::Gitlink);
        }
    }

    let tree_hex = String::from_utf8_lossy(&run_git(Some(repo), index_env, &[], &["write-tree"])?)
        .trim()
        .to_string();
    let source_id = SourceId::from_git_hash(&tree_hex)?;

    // Deterministic commit: author/committer = softfig-run, date = HEAD's
    // committer date (HEAD must exist; an unborn HEAD fails here cleanly).
    let committer_date = git(repo, &["show", "-s", "--format=%cI", "HEAD"])?;
    let commit_env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME", SNAPSHOT_AUTHOR_NAME),
        ("GIT_AUTHOR_EMAIL", SNAPSHOT_AUTHOR_EMAIL),
        ("GIT_COMMITTER_NAME", SNAPSHOT_AUTHOR_NAME),
        ("GIT_COMMITTER_EMAIL", SNAPSHOT_AUTHOR_EMAIL),
        ("GIT_AUTHOR_DATE", committer_date.as_str()),
        ("GIT_COMMITTER_DATE", committer_date.as_str()),
    ];
    let args: [&str; 6] = ["commit-tree", &tree_hex, "-p", "HEAD", "-m", SNAPSHOT_MESSAGE];
    let commit_hex =
        String::from_utf8_lossy(&run_git(Some(repo), commit_env, &[], &args)?)
            .trim()
            .to_string();
    let commit = hex::decode(&commit_hex)
        .map_err(|e| Error::Bundle(format!("commit-tree returned bad hex: {e}")))?;

    Ok(Snapshot {
        source_id,
        commit,
    })
}

/// The root commits of `HEAD` (the genesis the repo key is built from), as raw
/// object-id bytes. An unborn HEAD gives an empty list.
pub fn root_commits(repo: &Path) -> Result<Vec<Vec<u8>>> {
    if run_git(Some(repo), &[], &[], &["rev-parse", "--verify", "HEAD"]).is_err() {
        return Ok(Vec::new());
    }
    let out = git(repo, &["rev-list", "--max-parents=0", "HEAD"])?;
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| hex::decode(l.trim()).map_err(|e| Error::Bundle(format!("bad root {l}: {e}"))))
        .collect()
}

/// Build a `have/want` bundle on stdout (spec §4.3): `git bundle create -
/// <snapshot> --not <haves>`, where `haves` are first filtered to those this
/// repo still holds (a snapshot commit can age out via gc). A transient ref in
/// `refs/softfig/snap/` names the commit for the bundle (git refuses a raw sha)
/// and is deleted on every path; no persistent ref is written.
pub fn create_bundle(
    repo: &Path,
    source_id: &SourceId,
    commit: &[u8],
    haves: &[Vec<u8>],
) -> Result<Vec<u8>> {
    let commit_hex = hex::encode(commit);
    let present: Vec<String> = haves
        .iter()
        .map(hex::encode)
        .filter(|h| has_commit(repo, h))
        .collect();

    let refname = snapshot_ref(source_id);
    run_git(Some(repo), &[], &[], &["update-ref", &refname, &commit_hex])?;

    // A plain block (not an immediately-called closure), so the transient ref
    // is always deleted — even when the bundle build fails.
    let result = {
        let mut args: Vec<&str> = vec!["bundle", "create", "-", refname.as_str()];
        if !present.is_empty() {
            args.push("--not");
            for p in &present {
                args.push(p.as_str());
            }
        }
        run_git(Some(repo), &[], &[], &args)
    };

    let _ = run_git(Some(repo), &[], &[], &["update-ref", "-d", refname.as_str()]);
    result
}

// --- Runner side -----------------------------------------------------------

/// Enumerate the tips this mirror holds for a repo key (the `SourceHave` reply).
/// An absent mirror means a first job: no tips.
pub fn negotiate_tips(mirror: &Path) -> Result<HaveTips> {
    if !mirror.exists() {
        return Ok(HaveTips::default());
    }
    let out = git_runner(
        mirror,
        &["for-each-ref", "--format=%(objectname)", "refs/softfig/snap"],
    )?;
    let mut tips = Vec::new();
    let mut commits = Vec::new();
    for line in out.lines().take(TIP_LIMIT) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        tips.push(
            hex::decode(line).map_err(|e| Error::Bundle(format!("bad tip {line}: {e}")))?,
        );
        if let Ok(parent) = git_runner(mirror, &["rev-parse", &format!("{line}^")]) {
            let parent = parent.trim();
            if !parent.is_empty() {
                commits.push(
                    hex::decode(parent)
                        .map_err(|e| Error::Bundle(format!("bad parent {parent}: {e}")))?,
                );
            }
        }
    }
    Ok(HaveTips { tips, commits })
}

/// Ingest a bundle into the bare mirror at `refs/softfig/snap/<source_id>`
/// (spec §4.4). Initializes the mirror on first use. Runs under the runner
/// hardening config so hooks, fsmonitor, and every network transport are off
/// and the objects are fsck-checked on arrival.
pub fn ingest_bundle(mirror: &Path, source_id: &SourceId, bundle: &[u8]) -> Result<()> {
    if !mirror.exists() {
        run_git(None, &[], &[], &["init", "--bare", path_str(mirror, "mirror")?])?;
    }
    let mut tmp = tempfile::NamedTempFile::new()?;
    tmp.write_all(bundle)?;
    tmp.flush()?;
    let refname = snapshot_ref(source_id);
    let refspec = format!("+{refname}:{refname}");
    git_runner(
        mirror,
        &["fetch", path_str(tmp.path(), "bundle")?, refspec.as_str()],
    )?;
    Ok(())
}

/// Verify an ingested snapshot (spec §4.4): the mirror's snapshot ref must point
/// at the *offered* commit, and that commit's tree must equal the source id. A
/// mismatch rejects the job with `source-mismatch`.
pub fn verify_snapshot(
    mirror: &Path,
    source_id: &SourceId,
    snapshot_commit: &[u8],
) -> Result<()> {
    let commit_hex = hex::encode(snapshot_commit);
    let refname = snapshot_ref(source_id);

    let tip = git_runner(mirror, &["rev-parse", &format!("{refname}^{{commit}}")])
        .map_err(|_| Error::SourceMismatch(format!("snapshot ref {refname} not ingested")))?;
    if tip != commit_hex {
        return Err(Error::SourceMismatch(format!(
            "ingested {tip} != offered snapshot commit {commit_hex}"
        )));
    }
    let tree = git_runner(mirror, &["rev-parse", &format!("{commit_hex}^{{tree}}")])
        .map_err(|_| Error::SourceMismatch(format!("snapshot commit {commit_hex} not ingested")))?;
    if tree != source_id.hex() {
        return Err(Error::SourceMismatch(format!(
            "snapshot tree {tree} != source id {source_id}"
        )));
    }
    Ok(())
}

/// Materialize the snapshot into `src` with `read-tree` + `checkout-index`
/// (spec §4.4 — never `git archive`, which honors `export-subst`/`export-ignore`
/// and would silently change the tree). A gitlink materializes as an empty
/// directory (never populated); a symlink materializes as a symlink (never
/// followed). With `git_metadata`, a depth-1 throwaway repo of the snapshot
/// commit is added inside `src` for builds that call `git describe`/`rev-parse`.
pub fn materialize(
    mirror: &Path,
    source_id: &SourceId,
    snapshot_commit: &[u8],
    src: &Path,
    git_metadata: bool,
) -> Result<()> {
    let commit_hex = hex::encode(snapshot_commit);
    std::fs::create_dir_all(src)?;

    let tmp = tempfile::NamedTempFile::new()?;
    let index_path = path_str(tmp.path(), "temp index")?.to_string();
    let env: &[(&str, &str)] = &[
        ("GIT_INDEX_FILE", index_path.as_str()),
        ("GIT_DIR", path_str(mirror, "mirror")?),
        ("GIT_WORK_TREE", path_str(src, "src")?),
    ];

    run_git(None, env, RUNNER_GIT_CONFIG, &["read-tree", commit_hex.as_str()])?;
    run_git(None, env, RUNNER_GIT_CONFIG, &["checkout-index", "-a", "-f"])?;

    if git_metadata {
        add_git_metadata(src, mirror, source_id, commit_hex.as_str())?;
    }
    Ok(())
}

/// A depth-1 throwaway repo of the snapshot commit inside `src` (spec §4.4).
fn add_git_metadata(
    src: &Path,
    mirror: &Path,
    source_id: &SourceId,
    commit_hex: &str,
) -> Result<()> {
    // The throwaway repo runs under the SAME hardening: `core.hooksPath=/dev/null`
    // so a tree that smuggled a `.git/hooks` path (were it not already rejected
    // at ingest by fsck) can never execute on checkout.
    git_runner(src, &["init", "-q"])?;
    let refname = snapshot_ref(source_id);
    git_runner(
        src,
        &["fetch", "--depth=1", path_str(mirror, "mirror")?, refname.as_str()],
    )?;
    git_runner(src, &["checkout", "--detach", "-f", commit_hex])?;
    Ok(())
}

/// The object-format name for a source id, for diagnostics.
pub fn object_format(source_id: &SourceId) -> &'static str {
    source_id.format.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch git repo with a fixed identity (so commits are reproducible
    /// across the test run given a fixed committer date).
    fn git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let g = |args: &[&str]| {
            let ok = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
            assert!(ok.success(), "git {args:?} failed");
        };
        g(&["init", "-q"]);
        g(&["config", "user.email", "t@t"]);
        g(&["config", "user.name", "t"]);
        g(&["config", "commit.gpgsign", "false"]);
        dir
    }

    #[test]
    fn snapshot_includes_dirty_and_untracked_excludes_ignored() {
        let dir = git_repo();
        std::fs::write(dir.path().join("tracked.txt"), "one\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "tracked.txt"]);
        g(&["commit", "-q", "-m", "c1"]);
        // Dirty the tracked file, add an untracked file, and an ignored one.
        std::fs::write(dir.path().join("tracked.txt"), "two\n").unwrap();
        std::fs::write(dir.path().join("untracked.txt"), "u\n").unwrap();
        std::fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "i\n").unwrap();

        let snap = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();

        // Materialize the snapshot into a fresh dir and inspect.
        let mirror = tempfile::tempdir().unwrap();
        let mirror_git = mirror.path().join("m.git");
        let bundle = create_bundle(dir.path(), &snap.source_id, &snap.commit, &[]).unwrap();
        ingest_bundle(&mirror_git, &snap.source_id, &bundle).unwrap();
        verify_snapshot(&mirror_git, &snap.source_id, &snap.commit).unwrap();
        let src = tempfile::tempdir().unwrap().path().join("src");
        materialize(&mirror_git, &snap.source_id, &snap.commit, &src, false).unwrap();

        assert_eq!(std::fs::read_to_string(src.join("tracked.txt")).unwrap(), "two\n");
        assert_eq!(std::fs::read_to_string(src.join("untracked.txt")).unwrap(), "u\n");
        assert!(!src.join("ignored.txt").exists(), "ignored file must be excluded");
    }

    #[test]
    fn snapshot_leaves_refs_index_worktree_byte_identical() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "a\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);
        std::fs::write(dir.path().join("f.txt"), "b\n").unwrap();
        std::fs::write(dir.path().join("new.txt"), "n\n").unwrap();

        let index_path = {
            let out = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(["rev-parse", "--absolute-git-dir"])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string() + "/index"
        };
        let before_index = std::fs::read(&index_path).unwrap();
        let before_refs = std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["for-each-ref"])
            .output()
            .unwrap()
            .stdout;
        let before_worktree = std::fs::read_to_string(dir.path().join("f.txt")).unwrap();

        let _snap = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();

        assert_eq!(std::fs::read(&index_path).unwrap(), before_index, "index must be byte-identical");
        let after_refs = std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["for-each-ref"])
            .output()
            .unwrap()
            .stdout;
        assert_eq!(after_refs, before_refs, "refs must be byte-identical");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("f.txt")).unwrap(),
            before_worktree,
            "worktree must be byte-identical"
        );
    }

    #[test]
    fn same_tree_on_same_head_yields_the_same_commit() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "x\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);

        let a = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let b = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        assert_eq!(a.commit, b.commit, "same tree on same HEAD must give the same commit");
        assert_eq!(a.source_id, b.source_id);
    }

    #[test]
    fn gitlinks_are_refused_by_default_and_ignored_when_asked() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "x\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);

        // A nested repo, cloned into the worktree and staged: git records a
        // gitlink (mode 160000) for the embedded repository.
        let sub_src = dir.path().join("subrepo");
        std::fs::create_dir_all(&sub_src).unwrap();
        let sg = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&sub_src)
                .args(args)
                .status()
                .expect("run git");
        };
        sg(&["init", "-q"]);
        sg(&["config", "user.email", "s@s"]);
        sg(&["config", "user.name", "s"]);
        std::fs::write(sub_src.join("g.txt"), "g\n").unwrap();
        sg(&["add", "g.txt"]);
        sg(&["commit", "-q", "-m", "sc1"]);
        std::process::Command::new("git")
            .args(["clone", "-q", sub_src.to_str().unwrap(), dir.path().join("sub").to_str().unwrap()])
            .status()
            .expect("clone subrepo");
        g(&["add", "sub"]);

        assert!(matches!(
            snapshot_repo(dir.path(), SubmodulePolicy::Refuse),
            Err(Error::Gitlink)
        ));
        assert!(snapshot_repo(dir.path(), SubmodulePolicy::Ignore).is_ok());
    }

    #[test]
    fn second_job_bundle_carries_only_deltas() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "one\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);

        let first = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let first_bundle = create_bundle(dir.path(), &first.source_id, &first.commit, &[]).unwrap();

        // Second job: a different tree (dirty), with the first snapshot tip as a have.
        std::fs::write(dir.path().join("f.txt"), "two\n").unwrap();
        let second = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let second_bundle = create_bundle(
            dir.path(),
            &second.source_id,
            &second.commit,
            std::slice::from_ref(&first.commit),
        )
        .unwrap();

        assert!(
            second_bundle.len() < first_bundle.len(),
            "a delta bundle ({} bytes) should be smaller than the full bundle ({} bytes)",
            second_bundle.len(),
            first_bundle.len()
        );
        assert_ne!(second_bundle, first_bundle);
    }

    #[test]
    fn tampered_bundle_is_rejected() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "x\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);
        let snap = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        let bundle = create_bundle(dir.path(), &snap.source_id, &snap.commit, &[]).unwrap();

        let mirror = tempfile::tempdir().unwrap().path().join("m.git");
        let mut tampered = bundle;
        // Flip a byte in the middle of the pack (not the header).
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        assert!(ingest_bundle(&mirror, &snap.source_id, &tampered).is_err());
    }

    #[test]
    fn tree_mismatch_is_rejected() {
        let dir = git_repo();
        std::fs::write(dir.path().join("f.txt"), "x\n").unwrap();
        let g = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .status()
                .expect("run git");
        };
        g(&["add", "f.txt"]);
        g(&["commit", "-q", "-m", "c1"]);

        let snap_a = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();
        // A different tree (dirty), snapshotted again.
        std::fs::write(dir.path().join("f.txt"), "y\n").unwrap();
        let snap_b = snapshot_repo(dir.path(), SubmodulePolicy::Refuse).unwrap();

        // A hostile bundle: advertised under snap_a's source-id ref, but
        // carrying snap_b's commit, whose tree is snap_b ( != snap_a ).
        let bundle =
            create_bundle(dir.path(), &snap_a.source_id, &snap_b.commit, &[]).unwrap();
        let mirror = tempfile::tempdir().unwrap().path().join("m.git");
        ingest_bundle(&mirror, &snap_a.source_id, &bundle).unwrap();

        // The ingested commit's tree (snap_b) must not match the offered
        // source id (snap_a).
        assert!(matches!(
            verify_snapshot(&mirror, &snap_a.source_id, &snap_b.commit),
            Err(Error::SourceMismatch(_))
        ));

        // A wrong source id (whose ref was never ingested) is also a mismatch.
        assert!(matches!(
            verify_snapshot(&mirror, &snap_b.source_id, &snap_b.commit),
            Err(Error::SourceMismatch(_))
        ));
    }
}
