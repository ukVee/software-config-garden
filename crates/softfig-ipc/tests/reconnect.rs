//! `call_reconnecting` rides out a transient keeperd restart by reconnecting,
//! but never blindly retries a request that may already have applied.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use softfig_ipc::{call_reconnecting, ReconnectError, Request, Response, RetryPolicy};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique, short unix-socket path under the temp dir (stays under the ~108
/// char `sun_path` limit).
fn unique_socket() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("softfig-ipc-recon-{pid}-{n}.sock"))
}

/// Read one `\n`-framed request line off the stream (scoped so the borrow is
/// released before we write the reply).
fn read_request_line(stream: &mut std::os::unix::net::UnixStream) -> String {
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let _ = reader.read_line(&mut line);
    line
}

#[test]
fn rides_out_a_restart_by_reconnecting() {
    let sock = unique_socket();
    let server_sock = sock.clone();

    // Socket is absent for the first ~120ms, then keeperd "comes back": binds,
    // accepts one request, replies Ok.
    let server = thread::spawn(move || {
        thread::sleep(Duration::from_millis(120));
        let listener = UnixListener::bind(&server_sock).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_request_line(&mut stream);
        let mut bytes = serde_json::to_vec(&Response::ok(json!({"hello": "world"}))).unwrap();
        bytes.push(b'\n');
        stream.write_all(&bytes).unwrap();
        stream.flush().unwrap();
    });

    let policy = RetryPolicy {
        budget: Duration::from_secs(3),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(60),
    };
    let req = Request::new("add_note", json!({}));
    let resp = call_reconnecting(&sock, &req, policy).expect("should reconnect and succeed");
    match resp {
        Response::Ok { data, .. } => assert_eq!(data["hello"], "world"),
        other => panic!("expected Ok, got {other:?}"),
    }

    server.join().unwrap();
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn post_send_drop_is_surfaced_not_blindly_retried() {
    let sock = unique_socket();
    let server_sock = sock.clone();
    let accepted = Arc::new(AtomicUsize::new(0));
    let server_accepted = accepted.clone();

    // keeperd accepts the request then dies before replying (drops the stream).
    // The client must see this as ambiguous and NOT reconnect — a committing
    // verb may already have applied.
    let server = thread::spawn(move || {
        let listener = UnixListener::bind(&server_sock).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        server_accepted.fetch_add(1, Ordering::SeqCst);
        let _ = read_request_line(&mut stream);
        drop(stream); // close without replying -> client reads EOF

        // Watch ~200ms for an (incorrect) retry connection.
        listener.set_nonblocking(true).unwrap();
        let mut extra = 0u32;
        for _ in 0..20 {
            match listener.accept() {
                Ok(_) => {
                    extra += 1;
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        extra
    });

    let policy = RetryPolicy {
        budget: Duration::from_secs(2),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(60),
    };
    let req = Request::new("add_backlog_item", json!({}));
    let err = call_reconnecting(&sock, &req, policy)
        .expect_err("a post-send drop must surface, not silently retry");
    assert!(
        matches!(err, ReconnectError::Ambiguous { .. }),
        "expected Ambiguous, got {err:?}"
    );

    let extra_connects = server.join().unwrap();
    assert_eq!(extra_connects, 0, "client must NOT reconnect after a post-send drop");
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "exactly one connection expected");
    let _ = std::fs::remove_file(&sock);
}

#[test]
fn unreachable_keeperd_yields_a_clear_bounded_error() {
    let sock = unique_socket(); // never bound

    let policy = RetryPolicy {
        budget: Duration::from_millis(200),
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(50),
    };
    let req = Request::new("set_item_status", json!({}));

    let start = Instant::now();
    let err = call_reconnecting(&sock, &req, policy).expect_err("no listener -> must error");
    let elapsed = start.elapsed();

    match &err {
        ReconnectError::Unreachable {
            attempts, socket, ..
        } => {
            assert!(*attempts >= 1);
            assert_eq!(socket, &sock);
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
    // Actionable message, not a bare "Connection closed", and it names the socket.
    let msg = err.to_string();
    assert!(msg.contains("unreachable"), "message not actionable: {msg}");
    // Respects the ~200ms budget (ECONNREFUSED returns instantly, so the only
    // wall-clock is the backoff sleeps).
    assert!(elapsed < Duration::from_secs(2), "exceeded budget: {elapsed:?}");
}
