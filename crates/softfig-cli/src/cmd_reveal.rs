//! `softfig reveal <path>` — write the plaintext of a sealed Layer B
//! file to `$XDG_RUNTIME_DIR/softfig-reveal-*` (mode 0600) via the
//! daemon. Prints the temp file path to stdout; never prints plaintext
//! to stdout (avoids shell-history / scrollback / log-forwarder
//! capture).

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use softfig_ipc::{
    runtime_socket_path,
    verbs::{op, VaultRevealArgs, VaultRevealReply},
    ErrorKind,
};

use crate::cmd_daemon::try_daemon_call;

#[derive(Args, Debug)]
pub struct RevealArgs {
    /// Repo-relative path of the sealed file (e.g. `secrets/foo.toml`).
    pub path: String,
    /// M2c — reveal only the inline `<vault id="…">` region with this
    /// id. Repeat for multiple ids (one temp file per id, printed in
    /// the order supplied). Charset: `[a-zA-Z0-9_-]+`, max 64 bytes.
    #[arg(long = "id", value_name = "ID")]
    pub ids: Vec<String>,
    /// Override the socket path. Defaults to
    /// `$XDG_RUNTIME_DIR/softfig-keeperd.sock`.
    #[arg(long)]
    pub socket: Option<std::path::PathBuf>,
}

pub fn run(args: RevealArgs) -> Result<()> {
    let socket = args.socket.clone().unwrap_or_else(runtime_socket_path);

    // Client-side `--id` charset / length validation — fails fast so the
    // daemon doesn't have to round-trip a `BadArgs` for the obvious
    // typo.
    for id in &args.ids {
        validate_id(id)?;
    }

    // Cache the master password across multi-id calls so the user is
    // only prompted once per `softfig reveal` invocation (even when
    // `[reveal] idle_seconds = 0` would otherwise re-prompt per call).
    let mut cached_password: Option<String> = None;

    // Build the per-call id list: empty `--id` → one call with id=None
    // (M2b shape); ≥1 `--id` → one call per id.
    let ids_to_reveal: Vec<Option<String>> = if args.ids.is_empty() {
        vec![None]
    } else {
        args.ids.iter().cloned().map(Some).collect()
    };

    for id in ids_to_reveal {
        let mut request = VaultRevealArgs {
            path: args.path.clone(),
            master_password: cached_password.clone(),
            probe_only: false,
            id: id.clone(),
        };
        let reply = match call_reveal(&socket, &request) {
            Ok(r) => r,
            Err(CallError::NeedsPassword) => {
                let pw = match &cached_password {
                    Some(pw) => pw.clone(),
                    None => {
                        let p = rpassword::prompt_password("Master password: ")
                            .context("could not read master password from tty")?;
                        cached_password = Some(p.clone());
                        p
                    }
                };
                request.master_password = Some(pw);
                call_reveal(&socket, &request).map_err(|e| anyhow!("{e}"))?
            }
            Err(CallError::Other(msg)) => return Err(anyhow!("{msg}")),
            Err(CallError::DaemonAbsent) => {
                return Err(anyhow!(
                    "daemon not running — `softfig reveal` requires the daemon (Layer B has no direct-mode path)"
                ));
            }
        };
        // The path is the user-visible artifact; plaintext stays in the
        // temp file. Caller opens / less'es / pipes it themselves.
        println!("{}", reply.temp_path);
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<()> {
    const ID_MAX: usize = 64;
    if id.is_empty() {
        return Err(anyhow!("--id must be non-empty"));
    }
    if id.len() > ID_MAX {
        return Err(anyhow!("--id {:?} exceeds {} bytes", id, ID_MAX));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(anyhow!("--id {:?}: charset must be [a-zA-Z0-9_-]+", id));
    }
    Ok(())
}

#[derive(Debug)]
enum CallError {
    NeedsPassword,
    DaemonAbsent,
    Other(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::NeedsPassword => f.write_str("master password required"),
            CallError::DaemonAbsent => f.write_str("daemon not running"),
            CallError::Other(m) => f.write_str(m),
        }
    }
}

fn call_reveal(
    socket: &Path,
    args: &VaultRevealArgs,
) -> std::result::Result<VaultRevealReply, CallError> {
    let req_args =
        serde_json::to_value(args).map_err(|e| CallError::Other(format!("encode: {e}")))?;
    match try_daemon_call(socket, op::VAULT_REVEAL, req_args) {
        Ok(Some(reply)) => {
            let r: VaultRevealReply = serde_json::from_value(reply)
                .map_err(|e| CallError::Other(format!("decode: {e}")))?;
            Ok(r)
        }
        Ok(None) => Err(CallError::DaemonAbsent),
        Err(softfig_ipc::ClientError::Daemon {
            kind: ErrorKind::MasterPasswordRequired,
            message,
        }) => {
            // Status-only kind: the caller should prompt.
            let _ = message;
            Err(CallError::NeedsPassword)
        }
        Err(e) => Err(CallError::Other(e.to_string())),
    }
}
