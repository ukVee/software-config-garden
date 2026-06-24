//! wire-loose-ends slice 003 integration: a fired §9 alert lands on the
//! **committed** coordination bus via the live growlightd→keeperd post leg, end
//! to end over a real keeperd socket.
//!
//! growlightd's [`NotifyDispatcher`], with its `BusEmit` seam bound to the
//! production [`KeeperdBusEmit`], posts a fired alert to keeperd's existing
//! `post_message` verb **as a client** — the FIRST growlightd→keeperd *write*,
//! the mirror of the one-way `tail_bus` *pull* the bus tailer already runs. We
//! drive the dispatcher against a real unlocked keeperd (same "no FUSE, watcher
//! off" harness as `growlight.rs`), then `tail_bus` the committed store and
//! assert exactly one `kind: alert` message from `growlightd` survives as durable
//! groupchat history — addressed `@human` for a human-attention alert, `@all` for
//! a routine one. A suppressed (deduped) re-fire commits nothing.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use softfig_growlightd::{KeeperdBusEmit, NotifyDispatcher, NotifyEvent, NotifyPolicy};
use softfig_ipc::verbs::{op, ChatMessage, TailBusReply};
use softfig_ipc::{Request, Response};
use softfig_keeperd::{Daemon, DaemonHandle, KeeperConfig};
use softfig_vault::{params::VaultParams, Vault};
use softfig_vcs::Repo;

const PASS: &[u8] = b"pw-test-12345";
const PASS_STR: &str = "pw-test-12345";

fn fast_params() -> VaultParams {
    let mut p = VaultParams::default();
    p.argon2.m_cost = 8;
    p.argon2.t_cost = 1;
    p.argon2.p_cost = 1;
    p
}

fn init_garden(garden: &Path) {
    let (_vault, session, _recovery) =
        Vault::init_with_params(garden, PASS, fast_params()).unwrap();
    Repo::init(garden, &session).unwrap();
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            if let Ok(stream) = UnixStream::connect(path) {
                drop(stream);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} did not appear", path.display());
}

fn send(socket: &Path, req: &Request) -> Response {
    let mut stream = UnixStream::connect(socket).unwrap();
    let mut bytes = serde_json::to_vec(req).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// A real, unlocked keeperd on a tempdir garden + socket (no FUSE, watcher off).
struct Keeper {
    sock: PathBuf,
    _handle: DaemonHandle,
    _tmp: tempfile::TempDir,
}

impl Keeper {
    fn start() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let garden = tmp.path().to_path_buf();
        init_garden(&garden);
        let sock = garden.join("sock");
        let config = KeeperConfig::new(&garden)
            .without_watcher()
            .with_socket(&sock);
        let handle = Daemon::new(config).start().unwrap();
        wait_for_socket(&sock);
        let resp = send(
            &sock,
            &Request::new(op::UNLOCK, serde_json::json!({ "passphrase": PASS_STR })),
        );
        assert!(matches!(resp, Response::Ok { .. }), "unlock: {resp:?}");
        Keeper {
            sock,
            _handle: handle,
            _tmp: tmp,
        }
    }

    /// The whole committed bus channel (the same read growlightd's tailer uses).
    fn tail(&self) -> Vec<ChatMessage> {
        let resp = send(
            &self.sock,
            &Request::new(op::TAIL_BUS, serde_json::json!({ "since": 0 })),
        );
        match resp {
            Response::Ok { data, .. } => {
                let reply: TailBusReply = serde_json::from_value(data).expect("TailBusReply decodes");
                reply.messages
            }
            other => panic!("tail_bus: {other:?}"),
        }
    }

    /// A dispatcher with the live committed-bus emitter bound to this keeperd. No
    /// GUI/log notifiers are registered: the `BusEmit` seam fires on any fresh,
    /// non-suppressed policy decision regardless of the notifier registry, so the
    /// committed post is exercised in isolation.
    fn dispatcher(&self) -> NotifyDispatcher {
        let mut d = NotifyDispatcher::with_policy(NotifyPolicy::new());
        d.set_bus_emit(Box::new(KeeperdBusEmit::new(self.sock.clone())));
        d
    }
}

#[test]
fn a_human_attention_alert_lands_once_on_the_committed_bus_addressed_human() {
    let keeper = Keeper::start();
    assert!(keeper.tail().is_empty(), "the bus starts empty");

    let mut dispatcher = keeper.dispatcher();

    // A human-attention alert fires → exactly one committed @human alert from
    // growlightd, carrying the event summary as the body.
    let chans = dispatcher.notify(&NotifyEvent::BlockedOnHuman { item: "004".into() }, 0);
    assert!(!chans.is_empty(), "the alert fired (non-suppressed)");

    let msgs = keeper.tail();
    assert_eq!(msgs.len(), 1, "exactly one alert committed to the bus");
    let m = &msgs[0];
    assert_eq!(m.from, "growlightd", "posted as the orchestrator");
    assert_eq!(m.kind, "alert", "kind: alert (the §4a alert history)");
    assert_eq!(m.to, "@human", "a human-attention alert is addressed @human");
    assert_eq!(m.body, "`004` is blocked on a human decision");

    // The same alert within the §9 dedup window is suppressed → nothing new
    // commits (the durable history is not spammed every iteration).
    let again = dispatcher.notify(&NotifyEvent::BlockedOnHuman { item: "004".into() }, 0);
    assert!(again.is_empty(), "the repeat is deduped");
    assert_eq!(keeper.tail().len(), 1, "no second committed message");
}

#[test]
fn a_routine_alert_broadcasts_to_all_on_the_committed_bus() {
    let keeper = Keeper::start();
    let mut dispatcher = keeper.dispatcher();

    // SliceComplete is not a human-attention event → it broadcasts @all (every
    // agent's lane), still committed as a durable kind:alert from growlightd.
    dispatcher.notify(&NotifyEvent::SliceComplete { part: "001".into() }, 0);

    let msgs = keeper.tail();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].from, "growlightd");
    assert_eq!(msgs[0].kind, "alert");
    assert_eq!(msgs[0].to, "@all", "a routine alert broadcasts to every lane");
    assert_eq!(msgs[0].body, "slice `001` complete");
}
