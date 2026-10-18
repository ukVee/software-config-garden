//! `softfig-runnerd` binary entry: parse args and hand off to the library's
//! [`softfig_runnerd::daemon`] core + [`softfig_runnerd::wire::WireServer`].
//!
//! The system unit (packaging) runs this as `softfig-runner` with
//! `--owner-uid` set to the laptop owner's uid. It serves two listeners: the
//! admin unix socket (owner-uid only) and the job wire listener (Noise,
//! one connection per job, slice 003).

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use softfig_runnerd::state::DEFAULT_STATE_ROOT;

/// Default job-listener address. A port is not pinned by the spec; this is a
/// stable default the two-device smoke (slice 008) can override.
const DEFAULT_RUNNER_LISTEN: &str = "0.0.0.0:9200";

struct Args {
    state_root: PathBuf,
    owner_uid: u32,
    admin_socket: PathBuf,
    runner_listen: String,
    mdns: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut state_root = PathBuf::from(DEFAULT_STATE_ROOT);
    let mut owner_uid: Option<u32> = std::env::var("SOFTFIG_RUNNER_OWNER_UID")
        .ok()
        .and_then(|v| v.parse().ok());
    let mut admin_socket: Option<PathBuf> = None;
    let mut runner_listen = DEFAULT_RUNNER_LISTEN.to_string();
    let mut mdns = true;

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
            "--runner-listen" => {
                runner_listen = it.next().ok_or("--runner-listen needs an address")?;
            }
            "--no-mdns" => {
                mdns = false;
            }
            "-h" | "--help" => {
                eprintln!(
                    "softfig-runnerd\n\n  --state-root <path>    (default {DEFAULT_STATE_ROOT})\n  --owner-uid <uid>      the uid allowed on the admin socket (or $SOFTFIG_RUNNER_OWNER_UID)\n  --admin-socket <path>  (default <state-root>/admin.sock)\n  --runner-listen <addr> (default {DEFAULT_RUNNER_LISTEN})\n  --no-mdns              disable the _softfig-runner._tcp announce"
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
        runner_listen,
        mdns,
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

    let runner = match softfig_runnerd::daemon::Runner::load(&args.state_root, args.owner_uid) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("softfig-runnerd: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The wire listener runs beside the admin socket. It reloads cert/accept/
    // serve per connection, so grants/revokes take effect live.
    let wire = match softfig_runnerd::wire::WireServer::bind(
        runner.state_root().clone(),
        &args.runner_listen,
    ) {
        Ok(w) => Arc::new(w),
        Err(e) => {
            eprintln!("softfig-runnerd: {e}");
            return ExitCode::FAILURE;
        }
    };
    let _mdns = if args.mdns {
        announce_mdns(&args.state_root, wire.local_addr().ok().map(|a| a.port()))
    } else {
        None
    };
    let wire_thread = {
        let wire = Arc::clone(&wire);
        std::thread::spawn(move || {
            if let Err(e) = wire.run() {
                eprintln!("softfig-runnerd wire listener: {e}");
            }
        })
    };

    if let Err(e) = runner.serve(&args.admin_socket) {
        eprintln!("softfig-runnerd: {e}");
        return ExitCode::FAILURE;
    }
    let _ = wire_thread.join();
    ExitCode::SUCCESS
}

/// Best-effort mDNS announce of `_softfig-runner._tcp` (spec §3.3). Failure is
/// non-fatal — multicast may be unavailable (headless), and the requester falls
/// back to the configured endpoint/relay. Returns the `ServiceDaemon` to keep
/// the registration alive for the process lifetime. **Manual smoke** on a real
/// interface.
fn announce_mdns(state_root: &std::path::Path, port: Option<u16>) -> Option<mdns_sd::ServiceDaemon> {
    let port = port?;
    let cert = softfig_runnerd::cert::StoredCert::load(&state_root.join("cert.toml")).ok()?;
    let device_id: [u8; 32] = hex::decode(cert.device_id.trim()).ok()?.try_into().ok()?;

    let daemon = mdns_sd::ServiceDaemon::new().ok()?;
    let ad = softfig_net::discovery::RunnerAdvertisement { device_id, port };
    let host = hostname();
    let host_name = format!("{host}.local.");
    let addrs = local_addrs();
    // Instance name uses the hostname so two runners on one host don't collide.
    let fullname = softfig_net::discovery::announce_runner(
        &daemon,
        &ad,
        &host,
        &host_name,
        &addrs,
    )
    .ok()?;
    let _ = fullname;
    Some(daemon)
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "softfig-runner".to_string())
}

fn local_addrs() -> Vec<IpAddr> {
    use std::net::UdpSocket;
    // Best-effort: find the address we'd advertise by opening a throwaway
    // socket and reading its local address. A fuller enumeration (all interface
    // addresses) is a follow-up; the announce is a hint only.
    let mut addrs = Vec::new();
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0")
        && sock.connect("8.8.8.8:80").is_ok()
        && let Ok(local) = sock.local_addr()
    {
        addrs.push(local.ip());
    }
    addrs
}
