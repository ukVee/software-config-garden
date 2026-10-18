//! `softfig-sandbox-forward` — the in-namespace TCP→unix forwarder (spec
//! remote-runner §7.2, slice 005).
//!
//! The fetch/egress sandbox's net namespace has loopback only; cargo's
//! `http_proxy` points at this forwarder, which listens on a loopback TCP
//! address and pumps each connection to the runner's allowlisting CONNECT proxy
//! on a Unix socket (bind-mounted into the sandbox). The forwarder does **not**
//! parse CONNECT or enforce the allowlist — that stays in runnerd, outside the
//! sandbox, where the `[serve] egress` list lives.
//!
//! It is spawned by `softfig-sandbox-init` (before Landlock/seccomp confine the
//! job), as a plain child that lives as long as the sandbox: when the command
//! exits, bwrap tears the namespaces down and this process is killed with them.
//! The forwarder is *our* trusted helper, not repo code, so it is deliberately
//! left outside the Landlock/seccomp layer.

use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: softfig-sandbox-forward <unix-socket> <listen-addr>");
        return ExitCode::from(2);
    }
    let socket = args[1].clone();
    let listen = args[2].clone();

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("softfig-sandbox-forward: bind {listen}: {e}");
            return ExitCode::from(1);
        }
    };

    for conn in listener.incoming() {
        let conn = match conn {
            Ok(c) => c,
            Err(_) => continue,
        };
        let socket = socket.clone();
        thread::spawn(move || {
            let upstream = match UnixStream::connect(&socket) {
                Ok(u) => u,
                Err(_) => return,
            };
            pump(conn, upstream);
        });
    }
    ExitCode::SUCCESS
}

/// Bidirectionally pump between the loopback client and the proxy socket, the
/// same half-close discipline as the runner's proxy: each direction copies
/// until that side EOFs, then shuts down the other side's write.
fn pump(mut a: TcpStream, mut b: UnixStream) {
    let mut a_read = match a.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut b_read = match b.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let a_to_b = thread::spawn(move || {
        let _ = std::io::copy(&mut a, &mut b_read);
        let _ = b_read.shutdown(Shutdown::Write);
    });
    let b_to_a = thread::spawn(move || {
        let _ = std::io::copy(&mut b, &mut a_read);
        let _ = a_read.shutdown(Shutdown::Write);
    });
    let _ = a_to_b.join();
    let _ = b_to_a.join();
}
