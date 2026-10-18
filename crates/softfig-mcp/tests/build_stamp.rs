//! release-pipeline slice 002: the built `softfig-mcp` binary's version
//! surface — the build stamp read off disk, and `--version`.

/// The built `softfig-mcp` carries the build stamp, so `softfig daemon status`
/// can read its version off disk without running it.
#[test]
fn the_built_binary_carries_the_build_stamp() {
    let bin = std::path::Path::new(env!("CARGO_BIN_EXE_softfig-mcp"));
    assert_eq!(
        softfig_ipc::compat::read_stamp(bin),
        softfig_ipc::compat::BinStamp::Stamped(softfig_ipc::compat::binary_version().to_string())
    );
}

/// `softfig-mcp --version` reports the workspace version and exits, without
/// reading stdin.
#[test]
fn version_flag_reports_the_workspace_version() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_softfig-mcp"))
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        concat!("softfig-mcp ", env!("CARGO_PKG_VERSION"), "\n")
    );
}
