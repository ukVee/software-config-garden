//! The fetch step's egress proxy (spec remote-runner §7.2, slice 005): an HTTP
//! CONNECT proxy that forwards **only** to the hosts in the `[serve] egress`
//! allowlist, so `cargo fetch` reaches `index.crates.io` & friends but a
//! non-allowlisted host (e.g. `example.com`) is refused at the proxy.
//!
//! **Mechanism (settled in slice 005, closing spec §15's "egress proxy
//! mechanism"):** runnerd runs this proxy on a **Unix socket**, and a tiny
//! *in-namespace* forwarder (the fetch-sandbox init shim) listens on loopback
//! and pumps to that socket. Chosen over pasta because:
//!
//! - pasta/passt is not installed on the reference laptop (Arch) and would add
//!   a setuid + a whole user-mode networking stack for one allowlisted CONNECT;
//! - a Unix socket is a filesystem object, so it is bind-mounted into the
//!   sandbox and reachable with **no** veth / port-forward — the sandbox's net
//!   namespace stays loopback-only (no routing table, no veth), matching spec
//!   §7.2 "loopback only, plus a forwarder";
//! - the allowlist decision stays in runnerd (outside the sandbox), where the
//!   `[serve] egress` list lives.
//!
//! This module binds a plain [`TcpListener`] (not the Unix socket) so it is
//! testable without bwrap; the Unix-socket listener is a one-line swap in the
//! fetch harness (slice 005 wiring).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use crate::error::{Error, Result};

/// Decide whether a CONNECT target host (with `port`) is allowed by the
/// `[serve] egress` allowlist. Entries are hostnames, matched case-insensitively
/// and exactly (no subdomain wildcards — the list is explicit). An entry may
/// pin a port as `host:port`.
pub fn host_allowed(host: &str, port: u16, allowlist: &[String]) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    allowlist.iter().any(|e| {
        let e = e.trim().to_ascii_lowercase();
        match e.rsplit_once(':') {
            Some((eh, ep)) => eh == host && ep.parse::<u16>().is_ok_and(|p| p == port),
            None => e == host,
        }
    })
}

/// A bidirectional byte stream the proxy can tunnel. Abstracted over
/// [`TcpStream`] (the testable listener) and [`UnixStream`] (the production
/// listener) so one `serve_conn` serves both.
pub(crate) trait Duplex: Read + Write + Send + 'static {
    fn try_clone(&self) -> std::io::Result<Self>
    where
        Self: Sized;
    fn shutdown_write(&self) -> std::io::Result<()>;
}

impl Duplex for TcpStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        TcpStream::try_clone(self)
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl Duplex for UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        UnixStream::try_clone(self)
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

/// Which kind of listener the proxy is bound to.
enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

/// A client connection, tagged with its listener kind.
pub enum Conn {
    Tcp(TcpStream),
    Unix(UnixStream),
}

/// A CONNECT proxy with an allowlist. Binds either a TCP address (testable) or
/// a Unix socket (production — bind-mounted into the fetch sandbox); `run`
/// serves each connection on its own thread (matching `softfig-net`'s
/// concurrency model).
pub struct EgressProxy {
    listener: Listener,
    allowlist: Vec<String>,
}

impl EgressProxy {
    /// Bind the proxy on a TCP `addr` with the given allowlist (for tests).
    pub fn bind(addr: &str, allowlist: Vec<String>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .map_err(|e| Error::Protocol(format!("egress proxy bind {addr}: {e}")))?;
        Ok(Self { listener: Listener::Tcp(listener), allowlist })
    }

    /// Bind the proxy on a Unix socket at `path` (production — the fetch
    /// harness bind-mounts the socket into the sandbox). The parent directory
    /// must exist; a stale socket is not unlinked (the caller owns the path).
    pub fn bind_unix(path: &Path, allowlist: Vec<String>) -> Result<Self> {
        let listener = UnixListener::bind(path)
            .map_err(|e| Error::Protocol(format!("egress proxy bind unix {}: {e}", path.display())))?;
        Ok(Self { listener: Listener::Unix(listener), allowlist })
    }

    /// The bound TCP address (for tests and the fetch harness's `http_proxy` env).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr> {
        match &self.listener {
            Listener::Tcp(l) => Ok(l.local_addr()?),
            Listener::Unix(_) => Err(Error::Protocol("a unix-socket proxy has no TCP address".into())),
        }
    }

    /// The underlying TCP listener, so a test can bound an accept.
    pub fn listener(&self) -> &TcpListener {
        match &self.listener {
            Listener::Tcp(l) => l,
            Listener::Unix(_) => panic!("listener() is TCP-only; use accept() for the unix listener"),
        }
    }

    /// Accept one client connection on either listener kind.
    pub fn accept(&self) -> std::io::Result<Conn> {
        match &self.listener {
            Listener::Tcp(l) => l.accept().map(|(s, _)| Conn::Tcp(s)),
            Listener::Unix(l) => l.accept().map(|(s, _)| Conn::Unix(s)),
        }
    }

    /// Serve connections until the listener errors.
    pub fn run(self: std::sync::Arc<Self>) -> Result<()> {
        loop {
            let conn = match self.accept() {
                Ok(c) => c,
                Err(e) => return Err(Error::Io(e)),
            };
            let me = std::sync::Arc::clone(&self);
            thread::spawn(move || {
                let _ = match conn {
                    Conn::Tcp(s) => me.serve_conn(s),
                    Conn::Unix(s) => me.serve_conn(s),
                };
            });
        }
    }

    /// Serve one client connection: read the CONNECT request, refuse a
    /// non-allowlisted host with `403`, otherwise establish the tunnel and pump
    /// bytes bidirectionally. Crate-internal: the public entry is [`Self::run`].
    pub(crate) fn serve_conn<S: Duplex>(&self, mut stream: S) -> Result<()> {
        let (host, port) = read_connect_target(&mut stream)?;
        if !host_allowed(&host, port, &self.allowlist) {
            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            let _ = stream.flush();
            return Ok(());
        }
        let upstream = TcpStream::connect((host.as_str(), port))
            .map_err(|e| Error::Protocol(format!("egress dial {host}:{port}: {e}")))?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| Error::Protocol(format!("egress write 200: {e}")))?;
        stream
            .flush()
            .map_err(|e| Error::Protocol(format!("egress flush: {e}")))?;
        pump(stream, upstream);
        Ok(())
    }
}

/// Read and parse the CONNECT request head (`CONNECT host:port HTTP/1.1` +
/// headers through the blank line). Returns the target `(host, port)`.
fn read_connect_target<R: Read>(stream: &mut R) -> Result<(String, u16)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 64 * 1024 {
        stream
            .read_exact(&mut byte)
            .map_err(|e| Error::Protocol(format!("read proxy request: {e}")))?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if buf.len() >= 64 * 1024 {
        return Err(Error::Protocol("proxy request head too large".into()));
    }

    let first = buf
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or_default();
    let first = String::from_utf8_lossy(first);
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    if method != "CONNECT" {
        return Err(Error::Protocol(format!("expected CONNECT, got {method:?}")));
    }
    let target = parts.next().ok_or_else(|| Error::Protocol("CONNECT without a target".into()))?;
    split_host_port(target)
}

/// Split a `host:port` target into its parts (last colon splits, so an IPv6
/// literal is not supported — egress entries are hostnames).
fn split_host_port(target: &str) -> Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| Error::Protocol(format!("CONNECT target {target:?} has no :port")))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::Protocol(format!("CONNECT target {target:?} has a bad port")))?;
    Ok((host.to_ascii_lowercase(), port))
}

/// Bidirectionally pump bytes between two streams until either side closes.
fn pump<A: Duplex, B: Duplex>(mut a: A, mut b: B) {
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
        let _ = b_read.shutdown_write();
    });
    let b_to_a = thread::spawn(move || {
        let _ = std::io::copy(&mut b, &mut a_read);
        let _ = a_read.shutdown_write();
    });
    let _ = a_to_b.join();
    let _ = b_to_a.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener as StdListener;

    #[test]
    fn allowlist_matches_exact_host_and_pinned_port() {
        let list = vec!["index.crates.io".to_string(), "github.com:443".to_string()];
        assert!(host_allowed("index.crates.io", 443, &list));
        assert!(host_allowed("INDEX.CRATES.IO", 80, &list), "case-insensitive");
        assert!(host_allowed("github.com", 443, &list));
        assert!(!host_allowed("github.com", 80, &list), "port pin must match");
        assert!(!host_allowed("example.com", 443, &list));
        assert!(!host_allowed("crates.io", 443, &list), "no subdomain wildcard");
        assert!(!host_allowed("", 443, &list));
    }

    #[test]
    fn refused_host_gets_403() {
        let proxy = EgressProxy::bind("127.0.0.1:0", vec!["index.crates.io".into()]).unwrap();
        let addr = proxy.local_addr().unwrap();
        let proxy = std::sync::Arc::new(proxy);
        let me = std::sync::Arc::clone(&proxy);
        let handle = thread::spawn(move || me.serve_conn(me.listener().accept().unwrap().0));

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp);
        handle.join().unwrap().unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "resp = {resp:?}");
    }

    #[test]
    fn allowlisted_host_tunnels_bytes() {
        // A one-shot echo server on loopback.
        let echo = StdListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_thread = thread::spawn(move || {
            let (mut s, _) = echo.accept().unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap();
            s.write_all(&buf[..n]).unwrap();
        });

        // Proxy allowlists loopback, so the CONNECT to the echo server is let
        // through.
        let allow = format!("127.0.0.1:{}", echo_addr.port());
        let proxy = EgressProxy::bind("127.0.0.1:0", vec![allow]).unwrap();
        let addr = proxy.local_addr().unwrap();
        let proxy = std::sync::Arc::new(proxy);
        let me = std::sync::Arc::clone(&proxy);
        let serve = thread::spawn(move || me.serve_conn(me.listener().accept().unwrap().0));

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                    echo_addr.port()
                )
                .as_bytes(),
            )
            .unwrap();

        // Read the 200 line + blank line.
        let mut resp = Vec::new();
        let mut byte = [0u8; 1];
        while !resp.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            resp.push(byte[0]);
        }
        assert!(resp.starts_with(b"HTTP/1.1 200"), "resp = {:?}", String::from_utf8_lossy(&resp));

        client.write_all(b"hello-through-the-proxy").unwrap();
        let mut back = [0u8; 32];
        let n = client.read(&mut back).unwrap();
        assert_eq!(&back[..n], b"hello-through-the-proxy");

        // Half-close the client's write side so the proxy's pump sees EOF and
        // the serve thread can finish: `pump` copies until *either* side closes,
        // and a real CONNECT client (cargo) closes its socket when done.
        client.shutdown(std::net::Shutdown::Write).unwrap();
        drop(client);

        echo_thread.join().unwrap();
        serve.join().unwrap().unwrap();
    }

    #[test]
    fn unix_socket_refuses_a_non_allowlisted_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("egress.sock");
        let proxy = EgressProxy::bind_unix(&path, vec!["index.crates.io".into()]).unwrap();
        let proxy = std::sync::Arc::new(proxy);
        let me = std::sync::Arc::clone(&proxy);
        let serve = thread::spawn(move || match me.accept().unwrap() {
            Conn::Unix(s) => me.serve_conn(s),
            Conn::Tcp(_) => panic!("expected a unix conn"),
        });

        let mut client = UnixStream::connect(&path).unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        let _ = client.read_to_string(&mut resp);
        serve.join().unwrap().unwrap();
        assert!(resp.starts_with("HTTP/1.1 403"), "resp = {resp:?}");
    }
}
