//! Smoke-test the collect helper binary (spec remote-runner §6 step 6, §8,
//! slice 006): it BLAKE3s the files matching the declared globs and skips
//! symlinks (never followed to a host file). Runs the real binary via
//! `CARGO_BIN_EXE`, which also forces cargo to build `softfig-sandbox-collect`
//! so the runnerd loopback test can locate it beside its own target dir.

use std::process::Command;

const COLLECT: &str = env!("CARGO_BIN_EXE_softfig-sandbox-collect");

#[test]
fn collect_hashes_matching_files_and_skips_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"world!").unwrap();
    // A symlink that matches the glob but must not be followed (its target is
    // outside the sandbox view; here it points at the host's /etc/passwd).
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("leak.txt")).unwrap();

    let out = Command::new(COLLECT)
        .arg("*.txt")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "collect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "only a.txt matches; the leak.txt symlink is skipped: {text:?}");

    let mut parts = lines[0].split('\t');
    let hash = parts.next().unwrap();
    let size = parts.next().unwrap();
    let path = parts.next().unwrap();
    assert_eq!(path, "a.txt");
    assert_eq!(size, "5", "a.txt is 5 bytes");
    assert_eq!(hash.len(), 64, "a BLAKE3 hex digest is 64 chars: {hash}");
}
