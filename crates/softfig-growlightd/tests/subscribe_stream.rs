//! Integration: boot growlightd on a real Unix socket, open a `subscribe`
//! stream, push events through the hub (standing in for the future agent
//! backend), and read them back as newline-framed `Event` frames. Proves the
//! first multi-frame verb works end to end and that fan-out reaches independent
//! socket connections.
//!
//! No keeperd and no agents are involved — the garden root is injected directly
//! and events are published via the daemon's hub, exactly the seam the slice-004
//! e2e test swaps a fake agent backend into.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use softfig_growlightd::{Daemon, GrowlightdConfig};
use softfig_ipc::connect;
use softfig_ipc::growlightd::{op, AgentDeltaKind, Event};
use softfig_ipc::Request;

fn boot(socket: PathBuf, garden: PathBuf) -> softfig_growlightd::DaemonHandle {
    Daemon::new(GrowlightdConfig::new(socket, garden))
        .start()
        .expect("daemon boots")
}

fn send_subscribe(stream: &mut std::os::unix::net::UnixStream) {
    let mut bytes = serde_json::to_vec(&Request::new(op::SUBSCRIBE, serde_json::Value::Null)).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
}

fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("condition not met within timeout");
}

#[test]
fn subscribe_streams_events_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let mut stream = connect(&socket).expect("client connects");
    send_subscribe(&mut stream);

    // Wait for the server side to register the subscription before publishing —
    // otherwise the events would race ahead of the subscriber and be dropped.
    wait_until(|| handle.daemon.hub.subscriber_count() >= 1);

    let events = vec![
        Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "hello"),
        Event::agent_delta("loop-1", AgentDeltaKind::Thinking, "let me think"),
        Event::agent_delta("loop-1", AgentDeltaKind::ToolCall, "edit(server.rs)"),
    ];
    for e in &events {
        handle.daemon.hub.publish(e.clone());
    }

    // Read them back as newline-framed Event JSON, in order.
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    for expected in &events {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read event frame");
        assert!(n > 0, "stream closed early");
        let got: Event = serde_json::from_str(line.trim_end()).expect("decode Event frame");
        assert_eq!(&got, expected);
    }

    handle.shutdown();
    handle.join().expect("accept loop exits cleanly");
}

#[test]
fn two_subscribers_both_receive_over_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let mut s1 = connect(&socket).unwrap();
    let mut s2 = connect(&socket).unwrap();
    send_subscribe(&mut s1);
    send_subscribe(&mut s2);
    wait_until(|| handle.daemon.hub.subscriber_count() >= 2);

    let event = Event::agent_delta("loop-1", AgentDeltaKind::Assistant, "broadcast");
    handle.daemon.hub.publish(event.clone());

    for s in [&s1, &s2] {
        let mut reader = BufReader::new(s.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let got: Event = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(got, event, "every socket subscriber gets the event");
    }

    handle.shutdown();
    handle.join().unwrap();
}

#[test]
fn a_subscribe_stream_ends_when_the_daemon_stops() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let mut stream = connect(&socket).unwrap();
    send_subscribe(&mut stream);
    wait_until(|| handle.daemon.hub.subscriber_count() >= 1);

    // No events ever flow; shutting the daemon down must end the stream (client
    // sees EOF) rather than hang.
    handle.shutdown();
    handle.join().expect("accept loop exits cleanly");

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read after shutdown");
    assert_eq!(n, 0, "the stream closes (EOF) once the daemon stops");
}
