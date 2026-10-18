//! `softfig-runnerd` binary entry: start the admin socket and serve it.
//!
//! The system unit (packaging, next slice) runs this as `softfig-runner` with
//! `--owner-uid` set to the laptop owner's uid. It generates the runner keys on
//! first start, loads the enforced `serve.toml`/`accept.toml`, and answers
//! `ping`/`status`/`enable`/`disable` over the admin socket. `grant`/`revoke`/
//! `apply`/`renew`/`revoke-cert`/`purge`/`toolchain` are wired with the CLI in
//! the same slice's later commits.

use std::path::PathBuf;
use std::process::ExitCode;

use softfig_runnerd::{
    admin::{AdminResponse, AdminSocket},
    config::{AcceptConfig, ServeConfig},
    keys::RunnerKeys,
    state::{StateRoot, DEFAULT_STATE_ROOT},
};

struct Args {
    state_root: PathBuf,
    owner_uid: u32,
    admin_socket: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut state_root = PathBuf::from(DEFAULT_STATE_ROOT);
    let mut owner_uid: Option<u32> = std::env::var("SOFTFIG_RUNNER_OWNER_UID")
        .ok()
        .and_then(|v| v.parse().ok());
    let mut admin_socket: Option<PathBuf> = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--state-root" => {
                state_root = PathBuf::from(it.next().ok_or("--state-root needs a path")?);
            }
            "--owner-uid" => {
                owner_uid = Some(
                    it.next()
                        .ok_or("--owner-uid needs an integer")?
                        .parse()
                        .map_err(|_| "--owner-uid must be an integer")?,
                );
            }
            "--admin-socket" => {
                admin_socket = Some(PathBuf::from(
                    it.next().ok_or("--admin-socket needs a path")?,
                ));
            }
            "-h" | "--help" => {
                eprintln!(
                    "softfig-runnerd\n\n  --state-root <path>   (default {DEFAULT_STATE_ROOT})\n  --owner-uid <uid>     the uid allowed on the admin socket (or $SOFTFIG_RUNNER_OWNER_UID)\n  --admin-socket <path> (default <state-root>/admin.sock)"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let owner_uid = owner_uid.ok_or(
        "an owner uid is required: pass --owner-uid or set SOFTFIG_RUNNER_OWNER_UID",
    )?;
    let admin_socket = admin_socket.unwrap_or_else(|| state_root.join("admin.sock"));

    Ok(Args {
        state_root,
        owner_uid,
        admin_socket,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("softfig-runnerd: {e}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = run(&args) {
        eprintln!("softfig-runnerd: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(args: &Args) -> softfig_runnerd::Result<()> {
    let root = StateRoot::new(&args.state_root);
    root.ensure_dirs()?;

    // First start: generate the runner keys into `keys/` (0600).
    if !root.keys_dir().join(softfig_runnerd::keys::TRANSPORT_KEY_FILE).exists() {
        eprintln!("softfig-runnerd: generating runner keys under {}", root.keys_dir().display());
        RunnerKeys::generate().persist(&root.keys_dir())?;
    }

    let serve_path = root.serve_toml();
    let mut serve = ServeConfig::load(&serve_path)?;
    let accept_path = root.accept_toml();
    let accept = AcceptConfig::load(&accept_path)?;

    let socket = AdminSocket::bind(&args.admin_socket, args.owner_uid)?;
    eprintln!(
        "softfig-runnerd: admin socket at {} (owner uid {})",
        args.admin_socket.display(),
        args.owner_uid
    );

    socket.run(|req| dispatch(req, &mut serve, &serve_path, &accept, &root, args.owner_uid))?;
    Ok(())
}

fn dispatch(
    req: &softfig_runnerd::admin::AdminRequest,
    serve: &mut ServeConfig,
    serve_path: &std::path::Path,
    accept: &AcceptConfig,
    root: &StateRoot,
    owner_uid: u32,
) -> AdminResponse {
    use serde_json::json;

    match req.verb.as_str() {
        "ping" => AdminResponse::ok(json!({ "pong": true })),
        "status" => status(serve, accept, root, owner_uid),
        "enable" => {
            serve.enabled = true;
            match serve.save(serve_path) {
                Ok(()) => AdminResponse::ok(json!({ "enabled": true })),
                Err(e) => AdminResponse::err(format!("enable failed: {e}")),
            }
        }
        "disable" => {
            serve.enabled = false;
            match serve.save(serve_path) {
                Ok(()) => AdminResponse::ok(json!({ "enabled": false })),
                Err(e) => AdminResponse::err(format!("disable failed: {e}")),
            }
        }
        other => AdminResponse::err(format!("unknown verb: {other}")),
    }
}

fn status(serve: &ServeConfig, accept: &AcceptConfig, root: &StateRoot, owner_uid: u32) -> AdminResponse {
    use serde_json::json;

    let keys_present = root.keys_dir().join(softfig_runnerd::keys::TRANSPORT_KEY_FILE).exists()
        && root.keys_dir().join(softfig_runnerd::keys::ATTEST_KEY_FILE).exists();

    let (transport_pubkey, attest_pubkey) = match RunnerKeys::load(&root.keys_dir()) {
        Ok(k) => (
            Some(hex::encode(k.transport_pubkey())),
            Some(hex::encode(k.attest_pubkey())),
        ),
        Err(_) => (None, None),
    };

    AdminResponse::ok(json!({
        "enabled": serve.enabled,
        "keys_present": keys_present,
        "transport_pubkey": transport_pubkey,
        "attest_pubkey": attest_pubkey,
        "cert_present": root.cert_toml().exists(),
        "accepted_requesters": accept.peer.iter().map(|p| p.device_id.clone()).collect::<Vec<_>>(),
        "state_root": root.root(),
        "owner_uid": owner_uid,
    }))
}
