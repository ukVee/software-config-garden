//! The runner daemon core: bind the admin socket and serve the verb set.
//!
//! Lives in the library (not just the binary) so the integration test can boot
//! a real [`Runner`] on a temp state root and drive it through the admin
//! socket with [`crate::admin::AdminClient`] — the same path `softfig runner
//! …` uses.

use std::path::Path;

use serde_json::json;

use crate::admin::{
    AdminResponse, AdminSocket, ApplyArgs, GrantArgs, GrantReply, RevokeArgs, RevokeCertArgs,
    RevokeReply, StoreCertArgs,
};
use crate::cert::{StoredCert, StoredRevocation};
use crate::config::{AcceptConfig, AcceptedPeer, ServeConfig};
use crate::error::Result;
use crate::keys::{RunnerKeys, ATTEST_KEY_FILE, TRANSPORT_KEY_FILE};
use crate::state::StateRoot;

/// The mutable runner state the admin socket verbs act on. Held across the
/// accept loop; each verb mutates the in-memory copies and persists its own
/// files (single-threaded: the accept loop serves one connection at a time).
pub struct Runner {
    serve: ServeConfig,
    accept: AcceptConfig,
    root: StateRoot,
    owner_uid: u32,
}

impl Runner {
    /// Load (or initialise) the runner state under `state_root`: generate keys
    /// on a genuinely fresh root, load `serve.toml`/`accept.toml`.
    pub fn load(state_root: &Path, owner_uid: u32) -> Result<Self> {
        let root = StateRoot::new(state_root);
        root.ensure_dirs()?;
        if !root.keys_dir().join(TRANSPORT_KEY_FILE).exists() {
            RunnerKeys::generate().persist(&root.keys_dir())?;
        }
        Ok(Self {
            serve: ServeConfig::load(&root.serve_toml())?,
            accept: AcceptConfig::load(&root.accept_toml())?,
            root,
            owner_uid,
        })
    }

    /// Bind the admin socket and serve verbs until the listener errors or the
    /// process exits. The `SO_PEERCRED` gate admits only `owner_uid`.
    pub fn serve(self, admin_socket: &Path) -> Result<()> {
        let socket = AdminSocket::bind(admin_socket, self.owner_uid)?;
        let mut runner = self;
        socket.run(|req| dispatch(req, &mut runner))?;
        Ok(())
    }
}

/// One admin request → response. The full verb set for slice 002; job
/// transport/sandboxing verbs land in later slices.
pub fn dispatch(req: &crate::admin::AdminRequest, runner: &mut Runner) -> AdminResponse {
    match req.verb.as_str() {
        "ping" => AdminResponse::ok(json!({ "pong": true })),
        "status" => status(runner),
        "enable" => enable(runner),
        "disable" => disable(runner),
        "grant" => grant(runner, &req.args),
        "revoke" => revoke(runner, &req.args),
        "apply" => apply(runner, &req.args),
        "store-cert" => store_cert(runner, &req.args),
        "revoke-cert" => revoke_cert(runner, &req.args),
        "purge" => purge(runner),
        "toolchain" => toolchain(runner, &req.args),
        other => AdminResponse::err(format!("unknown verb: {other}")),
    }
}

/// `status`: certificate expiry, accepted requesters, keys, and the enforced
/// `[serve]` table (the CLI compares this to the garden's `config/runner.toml`
/// `[serve]` to report drift).
fn status(runner: &Runner) -> AdminResponse {
    let (transport_pubkey, attest_pubkey) = match RunnerKeys::load(&runner.root.keys_dir()) {
        Ok(k) => (
            Some(hex::encode(k.transport_pubkey())),
            Some(hex::encode(k.attest_pubkey())),
        ),
        Err(_) => (None, None),
    };

    let cert = runner
        .root
        .cert_toml()
        .exists()
        .then(|| StoredCert::load(&runner.root.cert_toml()).ok())
        .flatten();

    let revocation = runner
        .root
        .revocation_toml()
        .exists()
        .then(|| StoredRevocation::load(&runner.root.revocation_toml()).ok())
        .flatten();

    AdminResponse::ok(json!({
        "enabled": runner.serve.enabled,
        "transport_pubkey": transport_pubkey,
        "attest_pubkey": attest_pubkey,
        "cert": cert,
        "revocation": revocation,
        "accepted_requesters": runner.accept.peer.iter().map(|p| p.device_id.clone()).collect::<Vec<_>>(),
        "serve": runner.serve,
        "state_root": runner.root.root(),
        "owner_uid": runner.owner_uid,
    }))
}

/// `enable`: ensure the runner keys exist (generate on a genuinely fresh
/// state), set `enabled = true`, and return the two public keys so the CLI can
/// ask keeperd to sign the certificate.
fn enable(runner: &mut Runner) -> AdminResponse {
    let keys_dir = runner.root.keys_dir();
    if (!keys_dir.join(TRANSPORT_KEY_FILE).exists()
        || !keys_dir.join(ATTEST_KEY_FILE).exists())
        && let Err(e) = RunnerKeys::generate().persist(&keys_dir)
    {
        return AdminResponse::err(format!("key generation failed: {e}"));
    }

    let keys = match RunnerKeys::load(&keys_dir) {
        Ok(k) => k,
        Err(e) => return AdminResponse::err(format!("loading runner keys: {e}")),
    };

    runner.serve.enabled = true;
    if let Err(e) = runner.serve.save(&runner.root.serve_toml()) {
        return AdminResponse::err(format!("enable failed: {e}"));
    }

    AdminResponse::ok(json!({
        "enabled": true,
        "transport_pubkey": hex::encode(keys.transport_pubkey()),
        "attest_pubkey": hex::encode(keys.attest_pubkey()),
    }))
}

fn disable(runner: &mut Runner) -> AdminResponse {
    runner.serve.enabled = false;
    match runner.serve.save(&runner.root.serve_toml()) {
        Ok(()) => AdminResponse::ok(json!({ "enabled": false })),
        Err(e) => AdminResponse::err(format!("disable failed: {e}")),
    }
}

/// `grant`: add (or refresh) a requester in `accept.toml` from the identity +
/// transport key + name the CLI read out of the ring.
fn grant(runner: &mut Runner, args: &serde_json::Value) -> AdminResponse {
    let args: GrantArgs = match serde_json::from_value(args.clone()) {
        Ok(a) => a,
        Err(e) => return AdminResponse::err(format!("grant args: {e}")),
    };
    let granted = runner.accept.grant(AcceptedPeer {
        device_id: args.device_id,
        transport_pubkey: args.transport_pubkey,
        name: args.name,
    });
    if let Err(e) = runner.accept.save(&runner.root.accept_toml()) {
        return AdminResponse::err(format!("grant failed: {e}"));
    }
    AdminResponse::ok(serde_json::to_value(GrantReply { granted }).unwrap())
}

/// `revoke`: remove a requester from `accept.toml` and purge its mirrors.
fn revoke(runner: &mut Runner, args: &serde_json::Value) -> AdminResponse {
    let args: RevokeArgs = match serde_json::from_value(args.clone()) {
        Ok(a) => a,
        Err(e) => return AdminResponse::err(format!("revoke args: {e}")),
    };
    let revoked = runner.accept.revoke(&args.device_id);
    if let Err(e) = runner.accept.save(&runner.root.accept_toml()) {
        return AdminResponse::err(format!("revoke failed: {e}"));
    }
    // Best-effort purge of that requester's mirrors (slice 004 populates
    // `repos/`); a missing dir is not an error.
    if revoked {
        let _ = std::fs::remove_dir_all(runner.root.repos_dir());
    }
    AdminResponse::ok(serde_json::to_value(RevokeReply { revoked }).unwrap())
}

/// `apply`: replace the enforced `serve.toml` with the `[serve]` table the CLI
/// pushed from the garden's `config/runner.toml` (spec §5.2).
fn apply(runner: &mut Runner, args: &serde_json::Value) -> AdminResponse {
    let args: ApplyArgs = match serde_json::from_value(args.clone()) {
        Ok(a) => a,
        Err(e) => return AdminResponse::err(format!("apply args: {e}")),
    };
    runner.serve = args.serve;
    if let Err(e) = runner.serve.save(&runner.root.serve_toml()) {
        return AdminResponse::err(format!("apply failed: {e}"));
    }
    AdminResponse::ok(json!({ "applied": true }))
}

/// `store-cert`: write the signed certificate to `cert.toml` (enable/renew).
fn store_cert(runner: &mut Runner, args: &serde_json::Value) -> AdminResponse {
    let args: StoreCertArgs = match serde_json::from_value(args.clone()) {
        Ok(a) => a,
        Err(e) => return AdminResponse::err(format!("store-cert args: {e}")),
    };
    if let Err(e) = args.cert.save(&runner.root.cert_toml()) {
        return AdminResponse::err(format!("store-cert failed: {e}"));
    }
    AdminResponse::ok(json!({ "stored": true }))
}

/// `revoke-cert`: store the device identity's signed revocation record locally.
fn revoke_cert(runner: &mut Runner, args: &serde_json::Value) -> AdminResponse {
    let args: RevokeCertArgs = match serde_json::from_value(args.clone()) {
        Ok(a) => a,
        Err(e) => return AdminResponse::err(format!("revoke-cert args: {e}")),
    };
    let record = StoredRevocation {
        device_id: args.device_id,
        serial: args.serial,
        signature: args.signature,
    };
    if let Err(e) = record.save(&runner.root.revocation_toml()) {
        return AdminResponse::err(format!("revoke-cert failed: {e}"));
    }
    AdminResponse::ok(json!({ "revoked": true }))
}

/// `purge`: clear the mirrors and caches (best-effort; empty until slices 004
/// and 006 populate them).
fn purge(runner: &mut Runner) -> AdminResponse {
    let mut purged = 0usize;
    for dir in [runner.root.repos_dir(), runner.root.cache_dir()] {
        if std::fs::remove_dir_all(&dir).is_ok() {
            purged += 1;
        }
    }
    AdminResponse::ok(json!({ "purged": purged }))
}

/// `toolchain list`: the toolchains `[serve]` declares this runner can serve.
/// `toolchain add` runs `rustup` as `softfig-runner`, which needs the human —
/// the CLI shells that and never reaches this socket.
fn toolchain(runner: &Runner, args: &serde_json::Value) -> AdminResponse {
    match args.get("action").and_then(|a| a.as_str()) {
        Some("list") => AdminResponse::ok(json!({ "toolchains": runner.serve.toolchains })),
        other => AdminResponse::err(format!("unknown toolchain action: {other:?}")),
    }
}
