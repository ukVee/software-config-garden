//! The minimal `/etc` every sandbox step sees (spec §7.1: "minimal `/etc` (ld
//! cache, ssl certs, a stub `passwd`)"). Binding the host's whole `/etc` would
//! expose its hostname, users, service configs and any credential a package
//! left there; the job only needs the dynamic-linker cache, the CA bundle and
//! enough of a user database for `getpwuid` to answer.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;

/// The stub user database: root plus the unprivileged identity jobs run as.
const PASSWD: &str = "root:x:0:0:root:/root:/usr/bin/nologin\n\
                      job:x:1000:1000:job:/home/job:/usr/bin/nologin\n\
                      nobody:x:65534:65534:nobody:/:/usr/bin/nologin\n";
const GROUP: &str = "root:x:0:\njob:x:1000:\nnogroup:x:65534:\n";

/// The fetch step's etc, a sibling of the run etc `dir` that also carries a
/// `resolv.conf`.
pub fn fetch_etc_for(dir: &Path) -> PathBuf {
    dir.with_file_name("etc-fetch")
}

/// Build a minimal etc at `dest` from the host's `host_etc`. `resolv.conf` is
/// copied only when `with_resolv` (the fetch profile); the run profile has no
/// network to resolve against. Symlinks in the host tree are followed and the
/// content copied, since their targets are not visible inside the sandbox.
pub fn build_minimal_etc(dest: &Path, host_etc: &Path, with_resolv: bool) -> Result<()> {
    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    fs::create_dir_all(dest)?;
    fs::write(dest.join("passwd"), PASSWD)?;
    fs::write(dest.join("group"), GROUP)?;
    copy_file_if_present(&host_etc.join("ld.so.cache"), &dest.join("ld.so.cache"))?;
    copy_tree_if_present(&host_etc.join("ssl/certs"), &dest.join("ssl/certs"))?;
    if with_resolv {
        copy_file_if_present(&host_etc.join("resolv.conf"), &dest.join("resolv.conf"))?;
    }
    Ok(())
}

fn copy_file_if_present(from: &Path, to: &Path) -> Result<()> {
    // `fs::copy` follows symlinks; a missing or dangling source is skipped.
    if from.is_file() {
        fs::copy(from, to)?;
    }
    Ok(())
}

fn copy_tree_if_present(from: &Path, to: &Path) -> Result<()> {
    if !from.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let path = entry?.path();
        let target = to.join(path.file_name().expect("read_dir entries have names"));
        if path.is_dir() {
            copy_tree_if_present(&path, &target)?;
        } else {
            copy_file_if_present(&path, &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_etc(dir: &Path) -> PathBuf {
        let etc = dir.join("host-etc");
        fs::create_dir_all(etc.join("ssl/certs")).unwrap();
        fs::write(etc.join("ld.so.cache"), "cache").unwrap();
        fs::write(etc.join("ssl/certs/ca.pem"), "ca").unwrap();
        fs::write(etc.join("resolv.conf"), "nameserver 1.1.1.1\n").unwrap();
        fs::write(etc.join("shadow"), "root:$6$secret::\n").unwrap();
        fs::write(etc.join("hostname"), "laptop\n").unwrap();
        etc
    }

    #[test]
    fn only_listed_files_are_visible() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = host_etc(tmp.path());
        let dest = tmp.path().join("etc");
        build_minimal_etc(&dest, &etc, false).unwrap();
        assert!(dest.join("ld.so.cache").is_file());
        assert!(dest.join("ssl/certs/ca.pem").is_file());
        assert!(dest.join("passwd").is_file());
        assert!(dest.join("group").is_file());
        assert!(!dest.join("shadow").exists());
        assert!(!dest.join("hostname").exists());
        assert!(!dest.join("resolv.conf").exists());
        let passwd = fs::read_to_string(dest.join("passwd")).unwrap();
        assert!(!passwd.contains("laptop"));
    }

    #[test]
    fn resolv_conf_only_for_the_fetch_etc() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = host_etc(tmp.path());
        let dest = fetch_etc_for(&tmp.path().join("etc"));
        build_minimal_etc(&dest, &etc, true).unwrap();
        assert!(dest.join("resolv.conf").is_file());
    }

    #[test]
    fn symlinked_certs_are_copied_by_content() {
        let tmp = tempfile::tempdir().unwrap();
        let etc = host_etc(tmp.path());
        let real = tmp.path().join("real.pem");
        fs::write(&real, "bundle").unwrap();
        std::os::unix::fs::symlink(&real, etc.join("ssl/certs/ca-bundle.crt")).unwrap();
        let dest = tmp.path().join("etc");
        build_minimal_etc(&dest, &etc, false).unwrap();
        let copied = dest.join("ssl/certs/ca-bundle.crt");
        assert!(!copied.is_symlink());
        assert_eq!(fs::read_to_string(copied).unwrap(), "bundle");
    }
}
