//! `softfig-runnerd` binary entry: parse args and hand off to the library's
//! [`softfig_runnerd::daemon`] core.
//!
//! The system unit (packaging) runs this as `softfig-runner` with
//! `--owner-uid` set to the laptop owner's uid. Job transport, sandboxing, and
//! the wire frames land in later slices.

use std::path::PathBuf;
use std::process::ExitCode;

use softfig_runnerd::state::DEFAULT_STATE_ROOT;

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

    match softfig_runnerd::daemon::Runner::load(&args.state_root, args.owner_uid) {
        Ok(runner) => {
            if let Err(e) = runner.serve(&args.admin_socket) {
                eprintln!("softfig-runnerd: {e}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("softfig-runnerd: {e}");
            ExitCode::FAILURE
        }
    }
}
