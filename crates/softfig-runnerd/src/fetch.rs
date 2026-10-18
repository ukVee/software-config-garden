//! The trusted fetch step (spec remote-runner §7.2, slice 005): `cargo fetch
//! --locked` against an extracted skeleton, inside the `profile_fetch` sandbox,
//! behind the allowlisting egress proxy. No repo-authored code runs here.
//!
//! Slice 005 lands the *mechanism* and its proof: the skeleton extraction and
//! the proxy primitives (chunk 1), and the Unix-socket proxy listener, the
//! in-namespace forwarder, the `profile_run_egress` variant and the
//! fetch-harness integration test (chunk 2). The actual job-lifecycle wiring —
//! invoking the fetch step inside [`crate::wire::WireServer::serve_source`] and
//! mapping its `toolchain-missing` failure to a `JobReject` — lands in slice
//! 006, when the run step runs. This module holds the toolchain check so both
//! slices share one definition.

use crate::config::ServeConfig;

/// The exact command the owner runs to install a toolchain the runner lacks
/// (spec §7.2: "the owner runs `softfig runner toolchain add <spec>`").
pub fn toolchain_add_command(spec: &str) -> String {
    format!("softfig runner toolchain add {spec}")
}

/// Whether a skeleton's pinned toolchain channel is one the runner serves.
///
/// `channel` is [`softfig_source::Skeleton::toolchain`] (a `rust-toolchain(.toml)`
/// channel, e.g. `"1.85.0"`); `serve.toolchains` is the `[serve] toolchains`
/// list (spec §5.2). `None` means satisfied (or no toolchain pinned, which
/// rustup resolves to its default). `Some(command)` carries the exact
/// `softfig runner toolchain add <spec>` the owner should run — the wire sends
/// `JobRejectReason::ToolchainMissing`, and this string rides the runner's log
/// (the `JobReject` frame has no message field, so the human reads it at the
/// runner, where the command runs anyway).
pub fn toolchain_missing(channel: Option<&str>, serve: &ServeConfig) -> Option<String> {
    let channel = channel?.trim();
    if channel.is_empty() || serve.toolchains.iter().any(|t| t.trim() == channel) {
        None
    } else {
        Some(toolchain_add_command(channel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serve(toolchains: &[&str]) -> ServeConfig {
        ServeConfig {
            toolchains: toolchains.iter().map(|s| s.to_string()).collect(),
            ..ServeConfig::default()
        }
    }

    #[test]
    fn missing_channel_gets_the_add_command() {
        let s = serve(&["stable"]);
        assert_eq!(
            toolchain_missing(Some("1.85.0"), &s).as_deref(),
            Some("softfig runner toolchain add 1.85.0")
        );
    }

    #[test]
    fn present_channel_is_satisfied() {
        let s = serve(&["stable", "1.85.0"]);
        assert_eq!(toolchain_missing(Some("1.85.0"), &s), None);
        assert_eq!(toolchain_missing(Some("stable"), &s), None);
    }

    #[test]
    fn no_pinned_toolchain_is_satisfied() {
        let s = serve(&[]);
        assert_eq!(toolchain_missing(None, &s), None);
    }
}
