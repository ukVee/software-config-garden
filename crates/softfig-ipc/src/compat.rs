//! Version compatibility: the build stamp, the axis report, the
//! client↔daemon handshake, and the installed-set check (release-pipeline
//! slice 002; `meta/spec-release.md` → "Versioning: more than one axis",
//! `meta/spec-install.md` workstream A).
//!
//! Three questions, three tools:
//!
//! - **Is this client the same build as the daemon it talks to?** Every
//!   [`Request`] carries the sender's [`binary_version`], and a daemon runs
//!   [`check_request`] before the verb: a stamped request from another build
//!   is refused with [`ErrorKind::VersionMismatch`](crate::ErrorKind), except
//!   for the lifecycle ops the remedy itself needs (`op::LIFECYCLE`). A daemon
//!   that predates the stamp can't refuse anything, so the clients that read
//!   `status` anyway (`softfig daemon status`, the TUI at start, growlightd at
//!   boot) also compare the reply's [`VersionAxes`] through
//!   [`StatusReply::version_check`].
//! - **Which compatibility axes does the daemon speak?** [`VersionAxes`], in
//!   keeperd's `status` reply.
//! - **Is the installed set one build?** [`SetReport::scan`] reads the build
//!   stamp out of each binary in [`INSTALLED_SET`] *without running it*, the
//!   way `go version <binary>` reads Go's embedded build info. That names a
//!   partial install, not only a stale daemon. Running `<bin> --version`
//!   instead would be unsafe: the binaries a partial install leaves behind are
//!   the old ones, and before this slice `softfig-tui` and `softfig-mcp` had no
//!   `--version` (the TUI would take over the terminal, the MCP server would
//!   read stdin).

use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::client::{call, connect};
use crate::proto::Request;
use crate::verbs::{op, StatusReply};

/// The build stamp: two markers back-to-back — this build's version, then this
/// build's identity (commit SHA + dirty). They are one contiguous byte string
/// in every binary that links this crate, so [`read_stamp`] finds both.
///
/// `v1` is the layout of each marker. A reader trusts only the layout it knows.
static BUILD_STAMP: &str = concat!(
    "\0softfig-build-stamp:v1:", env!("CARGO_PKG_VERSION"), "\0",
    "\0softfig-build-id:v1:", env!("SOFTFIG_BUILD_ID"), "\0",
);

/// The marker in front of the version.
const STAMP_PREFIX_LEN: usize = "\0softfig-build-stamp:v1:".len();
/// The marker in front of the build identity.
const BUILD_ID_PREFIX: &str = "\0softfig-build-id:v1:";

/// The longest version [`find_stamp`] accepts. Workspace versions are far
/// shorter; the bound stops a scan from reading a whole binary as a version.
const MAX_VERSION_LEN: usize = 64;
/// The longest build id [`find_build_id`] accepts (a 12-hex SHA + `-dirty`,
/// plus headroom for CI ids).
const MAX_BUILD_ID_LEN: usize = 128;

/// The stamp's bytes, read through [`std::hint::black_box`] so the optimizer
/// can't fold callers down to a copy of just the part they use. The whole
/// stamp has to exist in the image for [`read_stamp`] to find it.
fn stamp_bytes() -> &'static [u8] {
    std::hint::black_box(BUILD_STAMP).as_bytes()
}

/// This build's version: the workspace `CARGO_PKG_VERSION`, read out of the
/// build stamp.
///
/// It is a function and not a constant on purpose. The linker drops data that
/// nothing references, and every binary asks for its version (each
/// [`Request`] carries it, keeperd's `status` reports it). Reading it from the
/// stamp is what keeps the stamp in every binary.
pub fn binary_version() -> &'static str {
    let stamp = stamp_bytes();
    let rest = &stamp[STAMP_PREFIX_LEN..];
    let end = rest.iter().position(|&b| b == 0).expect("version is NUL-terminated");
    std::str::from_utf8(&rest[..end]).expect("CARGO_PKG_VERSION is UTF-8")
}

/// This build's identity: the commit (or CI build id) the version was built
/// from. Two builds at one version still differ here — what lets the install
/// swap name a same-version rebuild (release-pipeline task 077).
pub fn build_id() -> &'static str {
    let stamp = stamp_bytes();
    let marker = BUILD_ID_PREFIX.as_bytes();
    let at = stamp
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("build-id marker present in the stamp");
    let rest = &stamp[at + marker.len()..];
    let end = rest.iter().position(|&b| b == 0).expect("build id is NUL-terminated");
    std::str::from_utf8(&rest[..end]).expect("SOFTFIG_BUILD_ID is UTF-8")
}

/// The pack format version. `None`: this build has no pack runtime
/// (`meta/spec-packs.md` is design only). The runtime that lands owns the
/// real constant and sets it here.
pub const PACK_FORMAT_VERSION: Option<u32> = None;

/// The garden convention version. `None`: nothing in this build checks a
/// garden against `meta/conventions.md`, so there is no version to claim.
pub const GARDEN_CONVENTION_VERSION: Option<u32> = None;

/// Every compatibility axis a daemon speaks, reported by keeperd's `status`.
///
/// An axis this build doesn't have is `None`. It is written as an explicit
/// `null`, not left out, so a reader can see that the axis is known and empty.
/// A reply from a daemon that predates an axis also parses to `None`. For
/// compatibility those mean the same thing: neither daemon can serve that axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionAxes {
    /// The daemon's build ([`binary_version`]).
    pub binary: String,
    /// IPC protocol ([`crate::PROTOCOL_VERSION`]).
    pub ipc_protocol: u8,
    /// On-disk store schema (`softfig_store::db::SCHEMA_VERSION`).
    pub store_schema: u32,
    /// Replication wire protocol (`softfig_net::PROTOCOL_VERSION`).
    pub wire_protocol: u32,
    /// Queue-v2 TOML schema ([`crate::queue_v2::SCHEMA_VERSION`]).
    pub queue_v2_schema: u32,
    /// [`PACK_FORMAT_VERSION`].
    #[serde(default)]
    pub pack_format: Option<u32>,
    /// [`GARDEN_CONVENTION_VERSION`].
    #[serde(default)]
    pub garden_convention: Option<u32>,
}

impl VersionAxes {
    /// This build's axes. The store and wire versions are passed in because
    /// they live in crates this one doesn't depend on (`softfig-store`,
    /// `softfig-net`); keeperd depends on both.
    pub fn this_build(store_schema: u32, wire_protocol: u32) -> Self {
        Self {
            binary: binary_version().to_string(),
            ipc_protocol: crate::PROTOCOL_VERSION,
            store_schema,
            wire_protocol,
            queue_v2_schema: crate::queue_v2::SCHEMA_VERSION,
            pack_format: PACK_FORMAT_VERSION,
            garden_convention: GARDEN_CONVENTION_VERSION,
        }
    }
}

impl fmt::Display for VersionAxes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let opt = |v: Option<u32>| v.map_or_else(|| "none".to_string(), |v| v.to_string());
        write!(
            f,
            "binary {} · ipc v{} · store schema {} · wire v{} · queue-v2 schema {} · \
             pack format {} · garden convention {}",
            self.binary,
            self.ipc_protocol,
            self.store_schema,
            self.wire_protocol,
            self.queue_v2_schema,
            opt(self.pack_format),
            opt(self.garden_convention),
        )
    }
}

/// Which side of a mismatch is behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skew {
    /// The client is the newer build, so the running daemon is stale.
    ClientNewer,
    /// The client is the older build.
    ClientOlder,
    /// The builds differ but don't order: a version that doesn't parse, or two
    /// that differ only in build metadata.
    Unordered,
}

/// A client and a daemon that are not the same build.
///
/// Its `Display` is the refusal every consumer shows, worded from the
/// client's side as `meta/spec-install.md` workstream A asks: "your `softfig`
/// is newer/older than the running daemon — run `softfig upgrade` / cycle the
/// daemon".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMismatch {
    /// The client's build.
    pub client: String,
    /// The daemon's build. `None` when the daemon predates the stamp.
    pub daemon: Option<String>,
}

impl VersionMismatch {
    pub fn skew(&self) -> Skew {
        // A daemon with no stamp predates every stamped client.
        let Some(daemon) = &self.daemon else {
            return Skew::ClientNewer;
        };
        match (semver::Version::parse(&self.client), semver::Version::parse(daemon)) {
            (Ok(client), Ok(daemon)) => match client.cmp_precedence(&daemon) {
                Ordering::Greater => Skew::ClientNewer,
                Ordering::Less => Skew::ClientOlder,
                Ordering::Equal => Skew::Unordered,
            },
            _ => Skew::Unordered,
        }
    }
}

impl fmt::Display for VersionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let client = &self.client;
        let daemon = match &self.daemon {
            Some(v) => format!("the running daemon ({v})"),
            None => "the running daemon (which predates version stamping)".to_string(),
        };
        match self.skew() {
            Skew::ClientNewer => write!(
                f,
                "your `softfig` ({client}) is newer than {daemon} — cycle the daemon \
                 (`softfig daemon cycle`) so it runs the installed build"
            ),
            Skew::ClientOlder => write!(
                f,
                "your `softfig` ({client}) is older than {daemon} — run `softfig upgrade`, \
                 or restart this client if it was upgraded while running"
            ),
            Skew::Unordered => write!(
                f,
                "your `softfig` ({client}) does not match {daemon} — run `softfig upgrade`, \
                 then cycle the daemon (`softfig daemon cycle`)"
            ),
        }
    }
}

impl std::error::Error for VersionMismatch {}

/// Compare a client's build with a daemon's. Only the same version string
/// matches: two builds that differ only in build metadata are still two builds.
pub fn check(client: &str, daemon: Option<&str>) -> Result<(), VersionMismatch> {
    if daemon == Some(client) {
        return Ok(());
    }
    Err(VersionMismatch {
        client: client.to_string(),
        daemon: daemon.map(str::to_string),
    })
}

/// A daemon's gate on one request, from this build's point of view: refuse a
/// stamped request from another build.
///
/// An unstamped request is served. It comes from a script or from a client
/// that predates the stamp. The IPC protocol version still gates its wire
/// format, and [`SetReport::scan`] names an unstamped binary on disk.
///
/// The caller decides which ops skip the gate (`op::LIFECYCLE`).
pub fn check_request(req: &Request) -> Result<(), VersionMismatch> {
    match req.binary_version.as_deref() {
        Some(client) => check(client, Some(binary_version())),
        None => Ok(()),
    }
}

impl StatusReply {
    /// This client against the daemon that sent the reply. A reply without
    /// [`VersionAxes`] comes from a daemon that predates the stamp, so it is
    /// a mismatch too.
    pub fn version_check(&self) -> Result<(), VersionMismatch> {
        check(binary_version(), self.axes.as_ref().map(|a| a.binary.as_str()))
    }
}

/// Ask the daemon at `socket` whether it is this build, before a long-lived
/// client starts.
///
/// `Some` only for a real mismatch. A daemon that is absent, unreachable or
/// answers something unexpected gives `None`, because the caller's own error
/// path already reports those.
pub fn daemon_mismatch(socket: &Path) -> Option<VersionMismatch> {
    let mut stream = connect(socket).ok()?;
    let resp = call(&mut stream, &Request::new(op::STATUS, serde_json::Value::Null)).ok()?;
    let reply: StatusReply = serde_json::from_value(resp.into_result().ok()?).ok()?;
    reply.version_check().err()
}

/// The installed set: the binaries an install puts on disk and swaps all or
/// nothing (`meta/spec-release.md` → **Binary set**). This is the one copy in
/// code. `scripts/onboard-device.sh` `BINARIES=` restates it, in this order,
/// and a test holds the two together.
pub const INSTALLED_SET: [&str; 5] = [
    "softfig",
    "softfig-keeperd",
    "softfig-mcp",
    "softfig-tui",
    "softfig-growlightd",
];

/// The marker file a swap writes into the install directory before the first
/// rename and removes after the last. Its presence alone means a swap was
/// interrupted: the installed set reads PARTIAL even when the five binaries
/// happen to read as one consistent build (the same-version rebuild case).
pub const SWAP_IN_PROGRESS_MARKER: &str = ".softfig-swap-in-progress";

/// What [`read_stamp`] found in one binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinStamp {
    /// Carries a stamp for this version and build identity.
    Stamped { version: String, build_id: String },
    /// Readable, with no stamp: a build older than the stamp.
    Unstamped,
    /// No such file.
    Missing,
    /// Couldn't be read; the message says why.
    Unreadable(String),
}

/// The stamp a build of `version` carries. Tests use it to fake an installed
/// binary of another build.
pub fn stamp_for(version: &str) -> Vec<u8> {
    stamp_with_identity(version, "test")
}

/// The stamp a build of `version` built from `build_id` carries. The default
/// [`stamp_for`] uses a fixed placeholder id; tests that care about identity
/// pass a real one here.
pub fn stamp_with_identity(version: &str, build_id: &str) -> Vec<u8> {
    let mut bytes = stamp_bytes()[..STAMP_PREFIX_LEN].to_vec();
    bytes.extend_from_slice(version.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(BUILD_ID_PREFIX.as_bytes());
    bytes.extend_from_slice(build_id.as_bytes());
    bytes.push(0);
    bytes
}

/// Read the build stamp out of a binary on disk. Never executes it.
pub fn read_stamp(path: &Path) -> BinStamp {
    match std::fs::read(path) {
        Ok(bytes) => match (find_stamp(&bytes), find_build_id(&bytes)) {
            (Some(version), Some(build_id)) => BinStamp::Stamped { version, build_id },
            // Version stamp but no build-id marker: a build that predates the
            // identity. It reads as "unknown" so it never compares equal to a
            // real build id.
            (Some(version), None) => BinStamp::Stamped {
                version,
                build_id: "unknown".to_string(),
            },
            (None, _) => BinStamp::Unstamped,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => BinStamp::Missing,
        Err(e) => BinStamp::Unreadable(e.to_string()),
    }
}

/// The first well-formed stamp in `bytes`: the marker, a version that parses
/// as semver, then a NUL. Requiring all three means a stray copy of the
/// marker, followed by whatever bytes, is never read as a version.
fn find_stamp(bytes: &[u8]) -> Option<String> {
    let prefix = &stamp_bytes()[..STAMP_PREFIX_LEN];
    memchr::memmem::find_iter(bytes, prefix).find_map(|at| {
        let rest = &bytes[at + STAMP_PREFIX_LEN..];
        let end = rest.iter().take(MAX_VERSION_LEN + 1).position(|&b| b == 0)?;
        let version = std::str::from_utf8(&rest[..end]).ok()?;
        semver::Version::parse(version).ok()?;
        Some(version.to_string())
    })
}

/// The first well-formed build-id marker in `bytes`: the marker, a non-empty
/// id (no NUL), then a NUL. A build that predates the identity has no such
/// marker, and a stray copy followed by garbage is never read as an id.
fn find_build_id(bytes: &[u8]) -> Option<String> {
    let marker = BUILD_ID_PREFIX.as_bytes();
    memchr::memmem::find_iter(bytes, marker).find_map(|at| {
        let rest = &bytes[at + marker.len()..];
        let end = rest.iter().take(MAX_BUILD_ID_LEN + 1).position(|&b| b == 0)?;
        if end == 0 {
            return None;
        }
        let id = std::str::from_utf8(&rest[..end]).ok()?;
        Some(id.to_string())
    })
}

/// The build stamp of every binary in [`INSTALLED_SET`] in one directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetReport {
    pub dir: PathBuf,
    /// One entry per [`INSTALLED_SET`] member, in that order.
    pub bins: Vec<(&'static str, BinStamp)>,
    /// True when [`SWAP_IN_PROGRESS_MARKER`] exists in `dir` — a swap was
    /// interrupted mid-rename. The set reads PARTIAL whenever this is set,
    /// even if the five binaries themselves read as one consistent build.
    pub swap_in_progress: bool,
}

impl SetReport {
    /// Read the stamps of the installed set in `dir`.
    pub fn scan(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            bins: INSTALLED_SET
                .iter()
                .map(|&name| (name, read_stamp(&dir.join(name))))
                .collect(),
            swap_in_progress: dir.join(SWAP_IN_PROGRESS_MARKER).exists(),
        }
    }

    /// Scan the directory the running binary was started from. An install puts
    /// the whole set in one directory, so that is where the siblings are.
    pub fn scan_own_dir() -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or_else(|| io::Error::other(format!("{} has no parent directory", exe.display())))?;
        Ok(Self::scan(dir))
    }

    /// The one version every binary carries, or `None` for a partial install:
    /// a binary missing, unreadable or unstamped, or two versions in one set.
    pub fn consistent_version(&self) -> Option<&str> {
        // A swap interrupted mid-rename reads as partial even when the
        // binaries happen to agree on one version (a same-version rebuild).
        if self.swap_in_progress {
            return None;
        }
        let mut versions = self.bins.iter().map(|(_, stamp)| match stamp {
            BinStamp::Stamped { version, .. } => Some(version.as_str()),
            _ => None,
        });
        let first = versions.next()??;
        versions.all(|v| v == Some(first)).then_some(first)
    }

    /// The one `(version, build_id)` pair every binary carries, or `None` for
    /// a mixed set: a binary missing/unreadable/unstamped, two versions, or one
    /// version at two identities. This is the idempotency signal `stage_and_swap`
    /// keys on — same version, different build id is still a different build
    /// (release-pipeline task 077).
    pub fn consistent_identity(&self) -> Option<(&str, &str)> {
        if self.swap_in_progress {
            return None;
        }
        let mut ids = self.bins.iter().map(|(_, stamp)| match stamp {
            BinStamp::Stamped { version, build_id } => Some((version.as_str(), build_id.as_str())),
            _ => None,
        });
        let first = ids.next()??;
        ids.all(|v| v == Some(first)).then_some(first)
    }
}

impl fmt::Display for SetReport {
    /// One line. Consistent: `5/5 at <version> in <dir>`. Partial: `PARTIAL in
    /// <dir> — ` and each group of binaries by what was found.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = self.dir.display();
        if let Some(version) = self.consistent_version() {
            return write!(f, "{n}/{n} at {version} in {dir}", n = self.bins.len());
        }
        // Group in order of first appearance so the line reads like the set.
        let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
        for (name, stamp) in &self.bins {
            let label = match stamp {
                BinStamp::Stamped { version, .. } => format!("at {version}"),
                BinStamp::Unstamped => "unstamped, older than version stamping".to_string(),
                BinStamp::Missing => "missing".to_string(),
                BinStamp::Unreadable(e) => format!("unreadable ({e})"),
            };
            match groups.iter_mut().find(|(l, _)| *l == label) {
                Some((_, names)) => names.push(name),
                None => groups.push((label, vec![name])),
            }
        }
        let mut pieces: Vec<String> = Vec::new();
        // The marker is the headline of a partial report: its presence means a
        // swap was interrupted, whatever the binaries read as.
        if self.swap_in_progress {
            pieces.push(format!("swap in progress ({SWAP_IN_PROGRESS_MARKER} present)"));
        }
        pieces.extend(
            groups
                .iter()
                .map(|(label, names)| format!("{} {label} ({})", names.len(), names.join(", "))),
        );
        write!(f, "PARTIAL in {dir} — {}", pieces.join(" · "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamped(version: &str) -> Vec<u8> {
        let mut bytes = b"\x7fELF junk before".to_vec();
        bytes.extend_from_slice(&stamp_for(version));
        bytes.extend_from_slice(b"junk after");
        bytes
    }

    #[test]
    fn binary_version_is_the_workspace_version() {
        assert_eq!(binary_version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn this_test_binary_carries_its_own_stamp() {
        let exe = std::env::current_exe().unwrap();
        assert_eq!(
            read_stamp(&exe),
            BinStamp::Stamped {
                version: binary_version().to_string(),
                build_id: build_id().to_string()
            }
        );
    }

    #[test]
    fn find_stamp_reads_a_well_formed_stamp() {
        assert_eq!(find_stamp(&stamped("1.2.3-alpha.4")).as_deref(), Some("1.2.3-alpha.4"));
    }

    #[test]
    fn find_build_id_reads_a_well_formed_build_id() {
        assert_eq!(
            find_build_id(&stamp_with_identity("1.0.0", "abc123def456")).as_deref(),
            Some("abc123def456")
        );
    }

    #[test]
    fn build_id_is_present_and_not_the_version() {
        assert!(!build_id().is_empty());
        assert_ne!(build_id(), binary_version());
    }

    #[test]
    fn consistent_identity_names_same_version_different_builds() {
        let dir = tempfile::tempdir().unwrap();
        for (i, name) in INSTALLED_SET.iter().enumerate() {
            let id = if i == INSTALLED_SET.len() - 1 { "bbb" } else { "aaa" };
            std::fs::write(dir.path().join(name), stamp_with_identity("1.0.0", id)).unwrap();
        }
        let report = SetReport::scan(dir.path());
        assert_eq!(report.consistent_version(), Some("1.0.0"), "version agrees: {report}");
        assert_eq!(report.consistent_identity(), None, "identity disagrees: {report}");

        // A fully-matching set reads as one identity.
        let dir2 = tempfile::tempdir().unwrap();
        for name in INSTALLED_SET {
            std::fs::write(dir2.path().join(name), stamp_with_identity("1.0.0", "aaa")).unwrap();
        }
        let report2 = SetReport::scan(dir2.path());
        assert_eq!(report2.consistent_identity(), Some(("1.0.0", "aaa")));
    }

    /// A bare marker followed by anything that isn't `<semver>\0` is not a
    /// stamp, and the scan goes on to the real one after it.
    #[test]
    fn find_stamp_skips_a_marker_that_is_not_followed_by_a_version() {
        let prefix = &stamp_bytes()[..STAMP_PREFIX_LEN];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(b"not a version\0");
        bytes.extend_from_slice(prefix);
        bytes.extend_from_slice(&[b'1'; MAX_VERSION_LEN + 8]); // no NUL in range
        assert_eq!(find_stamp(&bytes), None);
        bytes.extend_from_slice(&stamped("2.0.0"));
        assert_eq!(find_stamp(&bytes).as_deref(), Some("2.0.0"));
    }

    #[test]
    fn find_stamp_finds_nothing_in_an_unstamped_binary() {
        assert_eq!(find_stamp(b"\x7fELF an old build with no stamp"), None);
    }

    #[test]
    fn check_matches_only_the_same_version() {
        assert!(check("1.0.0", Some("1.0.0")).is_ok());
        assert!(check("1.0.0", Some("1.0.0+abc")).is_err());
        assert!(check("1.0.0", None).is_err());
    }

    #[test]
    fn a_newer_client_is_told_to_cycle_the_daemon() {
        let m = check("1.0.1", Some("1.0.0")).unwrap_err();
        assert_eq!(m.skew(), Skew::ClientNewer);
        let msg = m.to_string();
        assert!(msg.starts_with("your `softfig` (1.0.1) is newer than the running daemon (1.0.0)"), "{msg}");
        assert!(msg.contains("cycle the daemon"), "{msg}");
    }

    #[test]
    fn an_older_client_is_told_to_upgrade() {
        let m = check("1.0.0-alpha.1", Some("1.0.0")).unwrap_err();
        assert_eq!(m.skew(), Skew::ClientOlder);
        let msg = m.to_string();
        assert!(msg.starts_with("your `softfig` (1.0.0-alpha.1) is older than the running daemon (1.0.0)"), "{msg}");
        assert!(msg.contains("run `softfig upgrade`"), "{msg}");
    }

    #[test]
    fn a_daemon_without_a_stamp_is_older_than_any_client() {
        let m = check("1.0.0", None).unwrap_err();
        assert_eq!(m.skew(), Skew::ClientNewer);
        assert!(m.to_string().contains("predates version stamping"), "{m}");
    }

    #[test]
    fn builds_that_do_not_order_get_both_remedies() {
        for daemon in ["1.0.0+other", "garbage"] {
            let m = check("1.0.0", Some(daemon)).unwrap_err();
            assert_eq!(m.skew(), Skew::Unordered, "{daemon}");
            let msg = m.to_string();
            assert!(msg.contains("does not match") && msg.contains("softfig upgrade") && msg.contains("cycle the daemon"), "{msg}");
        }
    }

    #[test]
    fn check_request_refuses_another_build_and_serves_an_unstamped_request() {
        let mut req = Request::new(op::LOG, serde_json::Value::Null);
        assert_eq!(req.binary_version.as_deref(), Some(binary_version()), "Request::new stamps");
        assert!(check_request(&req).is_ok());
        req.binary_version = Some("0.0.1".into());
        let m = check_request(&req).unwrap_err();
        assert_eq!(m.daemon.as_deref(), Some(binary_version()));
        req.binary_version = None;
        assert!(check_request(&req).is_ok());
    }

    #[test]
    fn axes_serialize_an_absent_axis_as_null_and_parse_a_missing_key_as_none() {
        let axes = VersionAxes::this_build(1, 1);
        let v = serde_json::to_value(&axes).unwrap();
        assert!(v.get("pack_format").unwrap().is_null());
        assert!(v.get("garden_convention").unwrap().is_null());
        let mut obj = v.as_object().unwrap().clone();
        obj.remove("pack_format");
        let back: VersionAxes = serde_json::from_value(obj.into()).unwrap();
        assert_eq!(back.pack_format, None);
        assert_eq!(
            axes.to_string(),
            format!(
                "binary {} · ipc v{} · store schema 1 · wire v1 · queue-v2 schema {} · pack format none · garden convention none",
                binary_version(),
                crate::PROTOCOL_VERSION,
                crate::queue_v2::SCHEMA_VERSION
            )
        );
    }

    fn write_set(dir: &Path, stamps: &[(&str, Option<&str>)]) {
        for (name, version) in stamps {
            let bytes = match version {
                Some(v) => stamped(v),
                None => b"\x7fELF old".to_vec(),
            };
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }

    #[test]
    fn a_consistent_set_reads_as_one_version() {
        let dir = tempfile::tempdir().unwrap();
        let all: Vec<_> = INSTALLED_SET.iter().map(|n| (*n, Some("1.0.0"))).collect();
        write_set(dir.path(), &all);
        let report = SetReport::scan(dir.path());
        assert_eq!(report.consistent_version(), Some("1.0.0"));
        assert_eq!(report.to_string(), format!("5/5 at 1.0.0 in {}", dir.path().display()));
    }

    /// Three of five replaced, one left at the old build, one left from before
    /// the stamp: a partial install, and the report names every binary.
    #[test]
    fn a_partial_install_is_detected_and_named() {
        let dir = tempfile::tempdir().unwrap();
        write_set(
            dir.path(),
            &[
                ("softfig", Some("1.0.1")),
                ("softfig-keeperd", Some("1.0.1")),
                ("softfig-mcp", Some("1.0.1")),
                ("softfig-tui", Some("1.0.0")),
                ("softfig-growlightd", None),
            ],
        );
        let report = SetReport::scan(dir.path());
        assert_eq!(report.consistent_version(), None);
        assert_eq!(
            report.to_string(),
            format!(
                "PARTIAL in {} — 3 at 1.0.1 (softfig, softfig-keeperd, softfig-mcp) · \
                 1 at 1.0.0 (softfig-tui) · \
                 1 unstamped, older than version stamping (softfig-growlightd)",
                dir.path().display()
            )
        );
    }

    #[test]
    fn a_missing_binary_makes_the_set_partial() {
        let dir = tempfile::tempdir().unwrap();
        let four: Vec<_> = INSTALLED_SET[..4].iter().map(|n| (*n, Some("1.0.0"))).collect();
        write_set(dir.path(), &four);
        let report = SetReport::scan(dir.path());
        assert_eq!(report.consistent_version(), None);
        assert!(report.to_string().ends_with("1 missing (softfig-growlightd)"), "{report}");
    }

    /// A swap-in-progress marker alone makes an otherwise-consistent set read
    /// PARTIAL: the same-version rebuild's mid-swap state, where all five
    /// binaries agree on the version but a rename is still owed.
    #[test]
    fn a_swap_marker_makes_an_otherwise_consistent_set_read_partial() {
        let dir = tempfile::tempdir().unwrap();
        for name in INSTALLED_SET {
            std::fs::write(dir.path().join(name), stamp_with_identity("1.0.0", "aaa")).unwrap();
        }
        let clean = SetReport::scan(dir.path());
        assert!(!clean.swap_in_progress);
        assert_eq!(clean.consistent_identity(), Some(("1.0.0", "aaa")));

        std::fs::write(dir.path().join(SWAP_IN_PROGRESS_MARKER), "version 1.0.0\n").unwrap();
        let marked = SetReport::scan(dir.path());
        assert!(marked.swap_in_progress);
        assert_eq!(marked.consistent_version(), None, "marker forces PARTIAL: {marked}");
        assert_eq!(marked.consistent_identity(), None);
        assert!(marked.to_string().contains("swap in progress"), "{marked}");
    }

    /// `INSTALLED_SET` is the code-side copy of the installed set; the
    /// onboarding script restates it and must agree, in the same order.
    #[test]
    fn the_onboard_script_installs_exactly_the_installed_set() {
        let script = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/onboard-device.sh"
        ))
        .unwrap();
        let line = script
            .lines()
            .find_map(|l| l.trim().strip_prefix("BINARIES=("))
            .expect("onboard-device.sh declares BINARIES=(…)");
        let listed: Vec<&str> = line.trim_end_matches(')').split_whitespace().collect();
        assert_eq!(listed, INSTALLED_SET);
    }

    #[test]
    fn daemon_mismatch_names_a_daemon_of_another_build() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("keeperd.sock");
        assert_eq!(daemon_mismatch(&socket), None, "no daemon: nothing to compare");

        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            BufReader::new(&stream).read_line(&mut String::new()).unwrap();
            let reply = StatusReply {
                state: "unlocked".into(),
                tip: None,
                garden_root: "/g".into(),
                protocol_version: crate::PROTOCOL_VERSION,
                relock_pending: false,
                relock_expires_at: None,
                relock_enabled: false,
                growlight_enabled: false,
                shared_key_divergence: None,
                axes: Some(VersionAxes { binary: "0.0.1".into(), ..VersionAxes::this_build(1, 1) }),
                exe: None,
            };
            let resp = crate::Response::ok(serde_json::to_value(reply).unwrap());
            let mut line = serde_json::to_vec(&resp).unwrap();
            line.push(b'\n');
            stream.write_all(&line).unwrap();
        });
        let m = daemon_mismatch(&socket).expect("a 0.0.1 daemon is another build");
        server.join().unwrap();
        assert_eq!(m.daemon.as_deref(), Some("0.0.1"));
        assert_eq!(m.skew(), Skew::ClientNewer);
    }

    /// Release-workflow gate (release-pipeline slice 004, slice 002's
    /// follow-up): the release profile's thin LTO must not strip the build
    /// stamp out of the program binaries. Run with `cargo test --release`
    /// after `cargo build --workspace --release --locked` so the release
    /// binaries sit in the profile dir this test binary is beside. The release
    /// workflow sets `EXPECTED_RELEASE_VERSION` to the tag (leading `v`
    /// stripped) so a tag that doesn't match the workspace version — or a
    /// release build that dropped the stamp — fails the release before upload.
    /// In a casual `cargo test` the check is best-effort: it reads whatever
    /// binaries are beside this test and skips if there are none.
    #[test]
    fn release_binaries_carry_the_build_stamp() {
        // This test binary lives at <profile>/deps/<name>; the program
        // binaries are built beside it in <profile>/.
        let exe = std::env::current_exe().unwrap();
        let profile_dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
        let expected = std::env::var("EXPECTED_RELEASE_VERSION").ok();

        let first = profile_dir.join(INSTALLED_SET[0]);
        if !first.exists() {
            match &expected {
                Some(_) => panic!(
                    "release binary set missing at {} — run `cargo build \
                     --workspace --release --locked` first",
                    profile_dir.display()
                ),
                None => {
                    eprintln!(
                        "skipping release-stamp check: no binaries at {}",
                        profile_dir.display()
                    );
                    return;
                }
            }
        }

        let report = SetReport::scan(&profile_dir);
        let want = match expected.as_deref() {
            Some(v) => v,
            None => binary_version(),
        };
        assert_eq!(
            report.consistent_version(),
            Some(want),
            "the release binary set is not one {want} build — thin LTO dropped \
             or mangled the stamp: {report}"
        );
    }
}
