//! Smoke-test the collect helper binary (spec remote-runner §6 step 6, §8,
//! slice 006): it BLAKE3s the files matching the declared globs and skips
//! symlinks (never followed to a host file). Runs the real binary via
//! `CARGO_BIN_EXE`, which also forces cargo to build `softfig-sandbox-collect`
//! so the runnerd loopback test can locate it beside its own target dir.

use std::path::Path;
use std::process::{Command, Output};

const COLLECT: &str = env!("CARGO_BIN_EXE_softfig-sandbox-collect");

/// Run the collector in `dir` over `globs`, under an address-space cap of
/// `cap_kib` when given (`ulimit -v`, inherited across the `exec`).
fn run_collect(dir: &Path, globs: &[&str], cap_kib: Option<u32>) -> Output {
    let mut cmd = match cap_kib {
        Some(kib) => {
            let mut c = Command::new("sh");
            c.arg("-c").arg(format!("ulimit -v {kib} && exec \"$0\" \"$@\"")).arg(COLLECT);
            c
        }
        None => Command::new(COLLECT),
    };
    cmd.args(globs).current_dir(dir).output().unwrap()
}

/// The collector's rows: one JSON object per stdout line, every line a row.
fn rows(out: Output) -> Vec<serde_json::Value> {
    assert!(out.status.success(), "collect failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not a JSON row ({e}): {l:?}")))
        .collect()
}

#[test]
fn a_newline_or_tab_in_a_name_cannot_inject_rows() {
    // m3: rows were bare `<hash>\t<size>\t<path>` lines, so this one file
    // printed as two — the second a row the tree's author wrote.
    let dir = tempfile::tempdir().unwrap();
    let forged = format!("x\n{}\t1\tforged.bin", "0".repeat(64));
    std::fs::write(dir.path().join(&forged), b"data").unwrap();

    let got = rows(run_collect(dir.path(), &["*"], None));
    assert_eq!(got.len(), 1, "one file, one row: {got:?}");
    assert_eq!(got[0]["path"], forged.as_str());
    assert_eq!(got[0]["size"], 4);
}

#[test]
fn a_file_larger_than_the_memory_cap_is_streamed() {
    // m3: each artifact was `fs::read` whole, so one big artifact could OOM
    // the unit. Under an address-space cap smaller than the file, only a
    // streaming hash finishes.
    const FILE_MIB: usize = 48;
    const CAP_KIB: u32 = 32 * 1024;
    let dir = tempfile::tempdir().unwrap();
    // The cap leaves the collector itself room to run, so a failure below is
    // the file's doing.
    assert!(rows(run_collect(dir.path(), &["*"], Some(CAP_KIB))).is_empty());

    let bytes: Vec<u8> = (0..FILE_MIB << 20).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("big.bin"), &bytes).unwrap();
    let got = rows(run_collect(dir.path(), &["big.bin"], Some(CAP_KIB)));
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["size"], bytes.len());
    assert_eq!(got[0]["blake3"], blake3::hash(&bytes).to_hex().as_str());
}

#[test]
fn collect_hashes_matching_files_and_skips_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
    std::fs::write(dir.path().join("b.bin"), b"world!").unwrap();
    // A symlink that matches the glob but must not be followed (its target is
    // outside the sandbox view; here it points at the host's /etc/passwd).
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("leak.txt")).unwrap();

    let got = rows(run_collect(dir.path(), &["*.txt"], None));
    assert_eq!(got.len(), 1, "only a.txt matches; the leak.txt symlink is skipped: {got:?}");
    assert_eq!(got[0]["path"], "a.txt");
    assert_eq!(got[0]["size"], 5, "a.txt is 5 bytes");
    assert_eq!(got[0]["blake3"], blake3::hash(b"hello").to_hex().as_str());
}
