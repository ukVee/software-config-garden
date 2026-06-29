//! The control half of the GUI (spec §11 tweak-knobs + force-stop, §8): the pure
//! command/intent model. A gesture in the (deferred) iced view becomes a
//! [`Command`]; [`Command::to_request`] turns it into the exact [`WireRequest`]
//! (which daemon + op + JSON args) a thin live binding sends. No iced, no socket —
//! the command→wire mapping is the tested proof. The deferred live send reuses
//! the already-tested [`softfig_ipc::call_reconnecting`], dialing the socket named
//! by [`WireRequest::daemon`]; there is no new client helper.
//!
//! Routing (LOCKED — spec §13 / the one-way bus bridge): the human input box
//! posts via **keeperd** `post_message` (the bus store lives in keeperd;
//! growlightd only *pulls* from it — there is no growlightd→keeperd post verb).
//! Every control verb (pause/resume/force_stop/set_policy) goes to **growlightd**.
//!
//! Bus addressing: the post args keep the sigil form (`from:@human`, `to:@all`),
//! exactly as keeperd's `post_message` expects; the `@` is stripped only on the
//! echoed [`softfig_ipc::growlightd::Event::BusMessage`] — and so on the optimistic
//! chat line ([`crate::state::App::push_human_post`]).
//!
//! `set_policy` is a wire contract whose daemon handler is deferred to the
//! admission-governor phase (see [`softfig_ipc::growlightd::op::SET_POLICY`]); the
//! GUI's knobs panel builds the intent now and is ready when the handler lands.

use serde_json::Value;

use softfig_ipc::growlightd::{
    op as gop, ForceStopArgs, PolicySummary, SetPolicyArgs, SetResourcesArgs, StopLevel,
};
use softfig_ipc::verbs::{op as kop, PostMessageArgs};

/// The sender every human bus post carries — the human is a first-class member,
/// never an agent slug (mirrors the CLI `say` path's `human_say_args`). Its
/// sigil-stripped echo form is [`crate::state::HUMAN_FROM`].
pub const HUMAN_SENDER: &str = "@human";

/// Which daemon socket a [`WireRequest`] is sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Daemon {
    /// keeperd — owns the coordination-bus store (`post_message`).
    Keeperd,
    /// growlightd — the orchestrator control plane (control verbs).
    Growlightd,
}

/// A built IPC request: the daemon to dial, the op name, and the JSON args. The
/// deferred live binding sends it via [`softfig_ipc::call_reconnecting`] against
/// the matching socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRequest {
    /// Which daemon to send it to.
    pub daemon: Daemon,
    /// The op name.
    pub op: &'static str,
    /// The JSON args payload.
    pub args: Value,
}

/// A user control gesture, before it becomes a wire request. The view builds one
/// of these; [`Command::to_request`] turns it into a [`WireRequest`]. For a human
/// post the view *also* feeds [`crate::update::Message::HumanPosted`] to the
/// reducer for the optimistic line (the two carry the same `to`/`kind`/`body`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Post a human message to the coordination bus (keeperd). `to`/`kind` are the
    /// wire-token forms (`@all`/`@human`/slug; a bus kind token).
    PostHuman {
        /// Addressee (`@all` / `@human` / agent slug) — keeps the sigil.
        to: String,
        /// Bus kind token (`info`/`alert`/…).
        kind: String,
        /// Message body.
        body: String,
    },
    /// Engage the fleet admission gate (growlightd `pause`).
    Pause,
    /// Clear the fleet admission gate (growlightd `resume`).
    Resume,
    /// Force-stop one agent at a [`StopLevel`] (growlightd `force_stop`, §8).
    ForceStop {
        /// Target agent (work-stream) id.
        agent: String,
        /// Which stop level to apply.
        level: StopLevel,
    },
    /// Replace the per-device policy — the tweak knobs (growlightd `set_policy`).
    SetPolicy {
        /// The full replacement policy.
        policy: PolicySummary,
    },
    /// Adjust the GENTLE per-agent build-resource caps (growlightd `set_resources`,
    /// peer-isolation slice 003). A **partial** update: a `Some` field sets that
    /// knob, `None` leaves the current value untouched. All three knobs are SOFT
    /// throttles — there is no hard-cap field, so the gesture can only ever slow a
    /// build, never abort it (throttle-not-kill, by construction).
    SetResources {
        /// New `CARGO_BUILD_JOBS` (≥ 1), or `None` to leave it. Takes effect at the
        /// next spawn.
        build_jobs: Option<u32>,
        /// New `MemoryHigh` SOFT throttle (a systemd memory value), or `None`.
        /// Applied to running scopes immediately.
        memory_high: Option<String>,
        /// New `CPUWeight` (1..=10000), or `None`. Applied to running scopes
        /// immediately.
        cpu_weight: Option<u32>,
    },
}

impl Command {
    /// Build the [`WireRequest`] this command sends. Pure — the command→wire
    /// mapping is the tested heart of the control half. Fails only if a payload
    /// cannot serialize (a programmer error).
    pub fn to_request(&self) -> serde_json::Result<WireRequest> {
        Ok(match self {
            Command::PostHuman { to, kind, body } => WireRequest {
                daemon: Daemon::Keeperd,
                op: kop::POST_MESSAGE,
                args: serde_json::to_value(PostMessageArgs {
                    // The sender is forced to the human — a human post can never
                    // masquerade as an agent (mirrors `human_say_args`).
                    from: HUMAN_SENDER.to_string(),
                    to: to.clone(),
                    kind: kind.clone(),
                    body: body.clone(),
                })?,
            },
            Command::Pause => WireRequest {
                daemon: Daemon::Growlightd,
                op: gop::PAUSE,
                args: Value::Null,
            },
            Command::Resume => WireRequest {
                daemon: Daemon::Growlightd,
                op: gop::RESUME,
                args: Value::Null,
            },
            Command::ForceStop { agent, level } => WireRequest {
                daemon: Daemon::Growlightd,
                op: gop::FORCE_STOP,
                args: serde_json::to_value(ForceStopArgs {
                    agent: agent.clone(),
                    level: *level,
                })?,
            },
            Command::SetPolicy { policy } => WireRequest {
                daemon: Daemon::Growlightd,
                op: gop::SET_POLICY,
                args: serde_json::to_value(SetPolicyArgs { policy: *policy })?,
            },
            Command::SetResources {
                build_jobs,
                memory_high,
                cpu_weight,
            } => WireRequest {
                daemon: Daemon::Growlightd,
                op: gop::SET_RESOURCES,
                args: serde_json::to_value(SetResourcesArgs {
                    build_jobs: *build_jobs,
                    memory_high: memory_high.clone(),
                    cpu_weight: *cpu_weight,
                })?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_post_targets_keeperd_and_forces_the_human_sender() {
        let req = Command::PostHuman {
            to: "@all".into(),
            kind: "info".into(),
            body: "hi".into(),
        }
        .to_request()
        .unwrap();
        assert_eq!(req.daemon, Daemon::Keeperd);
        assert_eq!(req.op, "post_message");
        let args: PostMessageArgs = serde_json::from_value(req.args).unwrap();
        assert_eq!(args.from, "@human", "sender forced to the human");
        assert_eq!(args.to, "@all", "sigil form preserved on the wire");
        assert_eq!(args.kind, "info");
        assert_eq!(args.body, "hi");
    }

    #[test]
    fn pause_resume_target_growlightd_with_null_args() {
        assert_eq!(
            Command::Pause.to_request().unwrap(),
            WireRequest {
                daemon: Daemon::Growlightd,
                op: "pause",
                args: Value::Null
            }
        );
        assert_eq!(
            Command::Resume.to_request().unwrap(),
            WireRequest {
                daemon: Daemon::Growlightd,
                op: "resume",
                args: Value::Null
            }
        );
    }

    #[test]
    fn force_stop_maps_each_section8_level_to_its_wire_token() {
        for (level, token) in [
            (StopLevel::AfterSlice, "after_slice"),
            (StopLevel::AfterIteration, "after_iteration"),
            (StopLevel::HardKill, "hard_kill"),
        ] {
            let req = Command::ForceStop {
                agent: "loop-1".into(),
                level,
            }
            .to_request()
            .unwrap();
            assert_eq!(req.daemon, Daemon::Growlightd);
            assert_eq!(req.op, "force_stop");
            assert_eq!(req.args["agent"], "loop-1");
            assert_eq!(req.args["level"], token, "§8 level → wire token");
        }
    }

    #[test]
    fn set_policy_carries_the_knob_values_to_growlightd() {
        let policy = PolicySummary {
            max_concurrent_agents: 3,
            ctx_roll_pct: 50,
            ctx_handoff_pct: 60,
            session_5h_halt_pct: 85,
            session_7d_halt_pct: 90,
        };
        let req = Command::SetPolicy { policy }.to_request().unwrap();
        assert_eq!(req.daemon, Daemon::Growlightd);
        assert_eq!(req.op, "set_policy");
        assert_eq!(req.args["policy"]["max_concurrent_agents"], 3);
        assert_eq!(req.args["policy"]["ctx_roll_pct"], 50);
    }

    #[test]
    fn set_resources_carries_only_the_touched_knobs_to_growlightd() {
        let req = Command::SetResources {
            build_jobs: None,
            memory_high: Some("3G".into()),
            cpu_weight: Some(50),
        }
        .to_request()
        .unwrap();
        assert_eq!(req.daemon, Daemon::Growlightd);
        assert_eq!(req.op, "set_resources");
        // The untouched knob is omitted on the wire (partial update); the touched
        // ones carry their values.
        assert!(req.args.get("build_jobs").is_none(), "untouched knob omitted");
        assert_eq!(req.args["memory_high"], "3G");
        assert_eq!(req.args["cpu_weight"], 50);
    }
}
