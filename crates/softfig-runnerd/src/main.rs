//! `softfig-runnerd` binary entry: parse args and hand off to the library's
//! [`softfig_runnerd::daemon`] core + [`softfig_runnerd::wire::WireServer`].
//!
//! The system unit (packaging) runs this as `softfig-runner` with
//! `--owner-uid` set to the laptop owner's uid. It serves two listeners: the
//! admin unix socket (owner-uid only) and the job wire listener (Noise,
//! one connection per job, slice 003).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
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
    // `--run-job <spec> <result>`: the transient unit's payload. Runs the
    // executor from a serialized [`JobSpec`] and writes the [`JobReport`],
    // exiting with the job's code (slice 006 chunk 2).
    if std::env::args().any(|a| a == "--run-job") {
        let argv: Vec<String> = std::env::args().collect();
        return run_job_payload(&argv);
    }

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

/// Dispatch the transient-unit payload mode (`--run-job <spec> <result>`).
fn run_job_payload(argv: &[String]) -> ExitCode {
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        if a == "--run-job" {
            let (Some(spec), Some(result)) = (it.next(), it.next()) else {
                eprintln!("softfig-runnerd: --run-job needs <spec> and <result>");
                return ExitCode::from(2);
            };
            return match run_job_mode(Path::new(spec), Path::new(result)) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("softfig-runnerd run-job: {e}");
                    // 254: a runner-side failure (spec §9's runner failure code).
                    ExitCode::from(254)
                }
            };
        }
    }
    eprintln!("softfig-runnerd: --run-job needs <spec> and <result>");
    ExitCode::from(2)
}

/// The transient unit's payload: deserialize the spec, run the executor, write
/// the report, and return the job's exit code (or 254 for a runner-side
/// failure — the report's `error` field carries the reason).
fn run_job_mode(spec_path: &Path, result_path: &Path) -> Result<u8, String> {
    let spec: softfig_runnerd::JobSpec = {
        let bytes = std::fs::read(spec_path).map_err(|e| format!("read spec: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse spec: {e}"))?
    };
    let bins = softfig_runnerd::SandboxBinaries::next_to_runnerd()
        .map_err(|e| format!("resolve helper bins: {e}"))?;
    let serve = softfig_runnerd::ServeConfig {
        toolchains: spec.toolchains,
        egress: spec.egress,
        ..Default::default()
    };
    let offer = softfig_net::proto::JobOffer {
        cmd: spec.cmd,
        env: spec
            .env
            .into_iter()
            .map(|e| softfig_net::proto::EnvEntry { name: e.name, value: e.value })
            .collect(),
        network: spec.network,
        artifacts: spec.artifacts,
        ..Default::default()
    };

    // The run step's output is streamed, framed, to `run.log` beside the result,
    // so the runner can stream it back after the unit completes (unit-mode log
    // capture). Create it up front so an empty job still leaves a (empty) file.
    let log_path = result_path.with_file_name("run.log");
    let log_file =
        std::fs::File::create(&log_path).map_err(|e| format!("create log file: {e}"))?;
    let logs = softfig_runnerd::JobLogs::new();
    let sink = logs.sink().with_file(log_file);

    let report = match softfig_runnerd::executor::execute(&spec.ctx, &serve, &offer, &bins, Some(&sink)) {
        Ok(outcome) => softfig_runnerd::JobReport::ok(outcome),
        Err(softfig_runnerd::Error::ToolchainMissing(cmd)) => {
            softfig_runnerd::JobReport::err(format!("toolchain-missing: {cmd}"))
        }
        Err(e) => softfig_runnerd::JobReport::err(e.to_string()),
    };
    let code = report
        .outcome
        .as_ref()
        .map(|o| u8::try_from(o.exit_code).unwrap_or(254))
        .unwrap_or(254);
    std::fs::write(result_path, serde_json::to_vec(&report).map_err(|e| format!("encode report: {e}"))?)
        .map_err(|e| format!("write report: {e}"))?;
    Ok(code)
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
