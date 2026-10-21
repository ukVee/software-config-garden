//! m4: a `network = "egress"` run step reaches an allowlisted host through the
//! bound proxy socket and is refused on any other. Uses two loopback HTTP
//! servers (no external network), `curl --proxytunnel` for the CONNECT. Skips
//! loudly when bwrap / user namespaces / curl are unavailable.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;

use softfig_runnerd::executor::execute;
use softfig_runnerd::{SandboxBinaries, ServeConfig};
use softfig_sandbox::JobContext;

fn ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

fn sandbox_bins() -> SandboxBinaries {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    SandboxBinaries::new(
        profile_dir.join("softfig-sandbox-init"),
        profile_dir.join("softfig-sandbox-forward"),
        profile_dir.join("softfig-sandbox-collect"),
    )
}

/// A one-shot-per-connection HTTP server answering `200 hello`; returns its port.
fn serve_hello() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        }
    });
    port
}

fn run_curl(port: u16, allowed_port: u16) -> i32 {
    let work = tempfile::tempdir().unwrap();
    let ctx = JobContext {
        src: work.path().to_path_buf(),
        target_cache: tempfile::tempdir().unwrap().keep(),
        toolchain: tempfile::tempdir().unwrap().keep(),
        cargo_home: tempfile::tempdir().unwrap().keep(),
        etc: tempfile::tempdir().unwrap().keep(),
        scratch_size: 16 * 1024 * 1024,
    };
    let serve =
        ServeConfig { egress: vec![format!("127.0.0.1:{allowed_port}")], ..ServeConfig::default() };
    let url = format!("http://127.0.0.1:{port}/");
    let offer = softfig_net::proto::JobOffer {
        cmd: ["sh", "-c", &format!("curl -sf --max-time 10 --proxytunnel -o /dev/null {url}")]
            .map(String::from)
            .to_vec(),
        network: "egress".into(),
        cache: "fresh".into(),
        ..Default::default()
    };
    execute(&ctx, &serve, &offer, &sandbox_bins(), None).unwrap().exit_code
}

#[test]
fn egress_run_reaches_allowlisted_host_and_is_refused_elsewhere() {
    if !ok("bwrap", &["--version"]) || !ok("unshare", &["-Ur", "true"]) || !ok("curl", &["--version"])
    {
        eprintln!("SKIPPED: bwrap, user namespaces or curl unavailable; cannot run the egress test");
        return;
    }
    let allowed = serve_hello();
    let other = serve_hello();
    assert_eq!(run_curl(allowed, allowed), 0, "the allowlisted host must be reachable");
    assert_ne!(run_curl(other, allowed), 0, "a non-allowlisted host must be refused");
}
