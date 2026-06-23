//! Integration: the coordination-bus bridge end to end over a real socket.
//! Boot growlightd, open a `subscribe` stream, then run the bus tailer against a
//! FAKE keeperd source (a scripted message list standing in for keeperd's
//! `tail_bus`) and read the republished messages back as `Event::BusMessage`
//! frames. Proves slice-003's "an agent post surfaces to a subscribed client"
//! and "an alert event reaches a subscriber" through the live bridge + hub +
//! socket — with no keeperd and no agents (the `BusSource` seam is faked).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use softfig_growlightd::{spawn_bus_tailer, BusError, BusSource, Daemon, GrowlightdConfig};
use softfig_ipc::connect;
use softfig_ipc::growlightd::{op, Event};
use softfig_ipc::verbs::ChatMessage;
use softfig_ipc::Request;

/// A scripted [`BusSource`] standing in for keeperd's `tail_bus`: returns the
/// fixed messages numbered above `since`, so the bridge runs with no live keeperd.
#[derive(Debug)]
struct FakeSource {
    msgs: Vec<ChatMessage>,
}

impl BusSource for FakeSource {
    fn messages_since(&self, since: u32) -> Result<Vec<ChatMessage>, BusError> {
        Ok(self.msgs.iter().filter(|m| m.number > since).cloned().collect())
    }
}

fn msg(number: u32, from: &str, to: &str, kind: &str, body: &str) -> ChatMessage {
    ChatMessage {
        number,
        from: from.into(),
        to: to.into(),
        kind: kind.into(),
        body: body.into(),
        ts: "ts".into(),
    }
}

fn boot(socket: PathBuf, garden: PathBuf) -> softfig_growlightd::DaemonHandle {
    Daemon::new(GrowlightdConfig::new(socket, garden))
        .start()
        .expect("daemon boots")
}

fn send_subscribe(stream: &mut std::os::unix::net::UnixStream) {
    let mut bytes =
        serde_json::to_vec(&Request::new(op::SUBSCRIBE, serde_json::Value::Null)).unwrap();
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
fn an_agent_post_and_an_alert_reach_a_socket_subscriber_via_the_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("growlightd.sock");
    let handle = boot(socket.clone(), dir.path().join("garden"));

    let mut stream = connect(&socket).expect("client connects");
    send_subscribe(&mut stream);

    // Register the subscription BEFORE the tailer publishes, so nothing races
    // ahead of the subscriber and gets dropped.
    wait_until(|| handle.daemon.hub.subscriber_count() >= 1);

    // Now start the bridge against the fake keeperd: an agent's @all coord post
    // and a @human-addressed alert. Both must surface on the socket stream.
    let source = FakeSource {
        msgs: vec![
            msg(1, "agent-a", "@all", "coord-request", "rebase before merge"),
            msg(2, "agent-b", "@human", "alert", "disk almost full"),
        ],
    };
    let tailer = spawn_bus_tailer(
        handle.daemon.clone(),
        Box::new(source),
        Duration::from_millis(10),
    )
    .expect("tailer spawns");

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let expected = [
        // `@`-sigils stripped to the event's address form; chat kind passed through.
        Event::bus_message("agent-a", "all", "coord-request", "rebase before merge"),
        Event::bus_message("agent-b", "human", "alert", "disk almost full"),
    ];
    for want in &expected {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read event frame");
        assert!(n > 0, "stream closed early");
        let got: Event = serde_json::from_str(line.trim_end()).expect("decode Event frame");
        assert_eq!(&got, want);
    }

    handle.shutdown();
    let _ = tailer.join();
    handle.join().expect("accept loop exits cleanly");
}
