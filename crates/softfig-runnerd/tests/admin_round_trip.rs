//! Integration test: drive a real `Runner` on a temp state root through the
//! admin socket with the `AdminClient` — the same path `softfig runner …` uses.
//!
//! grant/revoke/apply round-trip against `accept.toml`/`serve.toml`, plus the
//! enable → store-cert → status flow that `softfig runner enable` performs.

use std::path::Path;
use std::time::Duration;

use softfig_runnerd::{
    admin::{AdminClient, ApplyArgs, GrantArgs, RevokeArgs, StoreCertArgs},
    cert::StoredCert,
    config::{AcceptConfig, ServeConfig},
    daemon::Runner,
};

/// Boot a runner on `state_root`/`socket` (in a thread) and return the client.
/// The socket is bound by the server thread; poll briefly for it to appear.
fn boot(state_root: &Path, socket: &Path) -> AdminClient {
    let owner_uid = current_uid();
    let runner = Runner::load(state_root, owner_uid).unwrap();
    let socket_owned = socket.to_path_buf();
    std::thread::spawn(move || {
        let _ = runner.serve(&socket_owned);
    });

    // The admin socket is bound before `serve` loops; wait for it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "admin socket was not bound");

    AdminClient::new(socket)
}

fn current_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and returns a plain integer.
    unsafe { libc::geteuid() }
}

fn sample_serve() -> ServeConfig {
    ServeConfig {
        enabled: false,
        max_jobs: 2,
        cpu_weight: 20,
        nice: 10,
        io_class: "idle".into(),
        memory_max: "8G".into(),
        tasks_max: 4096,
        time_max: "60m".into(),
        scratch_max: "20G".into(),
        cache_max: "60G".into(),
        on_battery: "allow".into(),
        on_battery_caps: None,
        toolchains: vec!["rust".into()],
        egress: vec!["index.crates.io".into()],
    }
}

fn status_serve(client: &AdminClient) -> ServeConfig {
    let resp = client.request("status", serde_json::json!({})).unwrap();
    assert!(resp.ok, "status: {:?}", resp.error);
    serde_json::from_value(resp.data.unwrap().get("serve").unwrap().clone()).unwrap()
}

#[test]
fn grant_revoke_apply_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let socket = dir.path().join("admin.sock");
    let client = boot(&state, &socket);

    // Grant a peer: it lands in accept.toml and is reported by status.
    let granted: softfig_runnerd::admin::GrantReply = client
        .call_typed(
            "grant",
            GrantArgs {
                device_id: "aa".repeat(32),
                transport_pubkey: "bb".repeat(32),
                name: "tablet".into(),
            },
        )
        .unwrap();
    assert!(granted.granted);

    let accept = AcceptConfig::load(&state.join("accept.toml")).unwrap();
    assert_eq!(accept.peer.len(), 1);
    assert_eq!(accept.peer[0].device_id, "aa".repeat(32));

    // A second grant of the same peer is an idempotent refresh.
    let again: softfig_runnerd::admin::GrantReply = client
        .call_typed(
            "grant",
            GrantArgs {
                device_id: "aa".repeat(32),
                transport_pubkey: "bb".repeat(32),
                name: "tablet".into(),
            },
        )
        .unwrap();
    assert!(!again.granted);
    assert_eq!(AcceptConfig::load(&state.join("accept.toml")).unwrap().peer.len(), 1);

    // Apply a serve config: it becomes the enforced copy on disk.
    let mut serve = sample_serve();
    serve.enabled = true;
    serve.max_jobs = 3;
    let applied: serde_json::Value = client
        .call_typed("apply", ApplyArgs { serve: serve.clone() })
        .unwrap();
    assert_eq!(applied["applied"], true);
    assert_eq!(ServeConfig::load(&state.join("serve.toml")).unwrap(), serve);
    assert_eq!(status_serve(&client), serve);

    // Revoke the peer: accept.toml empties.
    let revoked: softfig_runnerd::admin::RevokeReply = client
        .call_typed("revoke", RevokeArgs { device_id: "aa".repeat(32) })
        .unwrap();
    assert!(revoked.revoked);
    assert!(AcceptConfig::load(&state.join("accept.toml")).unwrap().peer.is_empty());
}

#[test]
fn enable_store_cert_and_status() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let socket = dir.path().join("admin.sock");
    let client = boot(&state, &socket);

    // enable: keys are returned, enabled flips true.
    let enabled: serde_json::Value = client.request("enable", serde_json::json!({})).unwrap().data.unwrap();
    let transport = enabled["transport_pubkey"].as_str().unwrap().to_string();
    let attest = enabled["attest_pubkey"].as_str().unwrap().to_string();
    assert_eq!(transport.len(), 64);
    assert_eq!(attest.len(), 64);
    assert_eq!(enabled["enabled"], true);

    // store-cert: the signed cert persists and status reports it.
    let cert = StoredCert {
        device_id: "00".repeat(32),
        runner_transport_pubkey: transport,
        runner_attest_pubkey: attest,
        serial: "11".repeat(16),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_000 + 90 * 24 * 60 * 60,
        signature: "22".repeat(64),
    };
    let stored: serde_json::Value = client
        .call_typed("store-cert", StoreCertArgs { cert: cert.clone() })
        .unwrap();
    assert_eq!(stored["stored"], true);
    assert_eq!(StoredCert::load(&state.join("cert.toml")).unwrap(), cert);

    let status = client.request("status", serde_json::json!({})).unwrap();
    assert!(status.ok);
    let data = status.data.unwrap();
    assert_eq!(data["cert"]["serial"], "11".repeat(16));
    assert_eq!(data["cert"]["expires_at"], cert.expires_at);
}

#[test]
fn foreign_uid_is_refused_over_the_client_path() {
    // The client connects as the test process's own uid; the gate should admit
    // it only when that uid equals the configured owner uid. Here we run the
    // server with a *different* owner uid, so the client is refused (EOF).
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let socket = dir.path().join("admin.sock");
    let runner = Runner::load(&state, current_uid().wrapping_add(1_000_000)).unwrap();
    let socket_owned = socket.clone();
    std::thread::spawn(move || {
        let _ = runner.serve(&socket_owned);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !socket.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    let client = AdminClient::new(&socket);
    // A refused peer: the server closes the socket without a byte, which the
    // client surfaces as a Protocol error (not a silent `ok:false`).
    assert!(client.request("ping", serde_json::json!({})).is_err());
}
