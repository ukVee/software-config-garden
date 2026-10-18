//! The requester's fallback + exit-code policy (spec remote-runner §9): which
//! runner-side failures trigger local fallback, and how a job outcome maps to a
//! process exit code. Pure and unit-tested so `softfig run`'s behavior is a
//! thin wrapper over a proven decision function.
//!
//! **Exit code.** `softfig run` exits with the job's own code; runner-side
//! failures (rejected, lost, source mismatch) exit **254** with the reason
//! printed.
//!
//! **Fallback** (decided default `local`) fires *exactly* on the §9 triggers:
//! no runner reachable within `connect_timeout`, an invalid or revoked
//! certificate, or a reject for `disabled`, `draining`, `on-battery` or
//! `busy-timeout`. It never fires on a job that ran and failed — that is a real
//! result.

use crate::runner::{JobOutcome, JobRejectReason};

use super::run_config::Fallback;

/// The exit code for a runner-side failure (spec §9).
pub const RUNNER_FAILURE_EXIT: i32 = 254;

/// Why the runner path failed before producing a result. The reason string is
/// what `softfig run` prints (and what the `ran LOCALLY: <reason>` line shows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunFailure {
    /// No runner was reachable within `connect_timeout`.
    NoRunner,
    /// The runner's certificate failed verification (bad signature, expired,
    /// wrong identity, or a handshake-static mismatch).
    InvalidCert,
    /// The runner's certificate serial is revoked.
    RevokedCert,
    /// The runner rejected the offer with a closed reason.
    Rejected(JobRejectReason),
}

impl RunFailure {
    /// The human-readable reason, for the `ran LOCALLY:` / 254 message.
    pub fn reason(&self) -> String {
        match self {
            Self::NoRunner => "no runner reachable".to_string(),
            Self::InvalidCert => "runner certificate invalid".to_string(),
            Self::RevokedCert => "runner certificate revoked".to_string(),
            Self::Rejected(r) => format!("runner rejected: {}", r.as_str()),
        }
    }
}

/// The closed set of reject reasons that trigger fallback (spec §9).
const FALLBACK_REJECT_REASONS: &[JobRejectReason] = &[
    JobRejectReason::Disabled,
    JobRejectReason::Draining,
    JobRejectReason::OnBattery,
    JobRejectReason::BusyTimeout,
];

/// Whether `failure` is a fallback trigger (spec §9). A reject for
/// `not-granted`, `toolchain-missing`, `limits-exceed` or `source-mismatch` is
/// *not* a trigger (a permanent config/trust error, not a transient
/// availability one), and a job that ran and failed is never routed through
/// this at all.
pub fn is_fallback_trigger(failure: &RunFailure) -> bool {
    match failure {
        RunFailure::NoRunner | RunFailure::InvalidCert | RunFailure::RevokedCert => true,
        RunFailure::Rejected(r) => FALLBACK_REJECT_REASONS.contains(r),
    }
}

/// The action to take when a fallback trigger fires, resolved from the
/// per-call `--fallback` override (if any) over the device's `[use] fallback`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FallbackAction {
    /// Run the command locally in the repo (the decided default).
    RunLocal,
    /// Retry until `wait_timeout` elapses, then give up.
    Wait,
    /// Exit 254 immediately.
    Fail,
}

/// Decide the fallback action for a failure. `None` when the failure is *not*
/// a trigger — the caller must exit 254 without falling back. `cli_override`
/// wins over `config_fallback` (spec §9 "Overrides: --fallback per call").
pub fn fallback_action(
    config_fallback: Fallback,
    cli_override: Option<Fallback>,
    failure: &RunFailure,
) -> Option<FallbackAction> {
    if !is_fallback_trigger(failure) {
        return None;
    }
    let mode = cli_override.unwrap_or(config_fallback);
    Some(match mode {
        Fallback::Local => FallbackAction::RunLocal,
        Fallback::Wait => FallbackAction::Wait,
        Fallback::Fail => FallbackAction::Fail,
    })
}

/// Map a job outcome to the process exit code (spec §9): the job's own code on
/// accept, 254 on reject (a reject is never a real result).
pub fn outcome_exit_code(outcome: &JobOutcome) -> i32 {
    match outcome {
        JobOutcome::Accepted(result) => result.exit_code,
        JobOutcome::Rejected(_) => RUNNER_FAILURE_EXIT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::JobResult;

    fn rejected(reason: JobRejectReason) -> RunFailure {
        RunFailure::Rejected(reason)
    }

    #[test]
    fn triggers_match_spec_9_exactly() {
        // Triggers.
        for f in [
            RunFailure::NoRunner,
            RunFailure::InvalidCert,
            RunFailure::RevokedCert,
            rejected(JobRejectReason::Disabled),
            rejected(JobRejectReason::Draining),
            rejected(JobRejectReason::OnBattery),
            rejected(JobRejectReason::BusyTimeout),
        ] {
            assert!(is_fallback_trigger(&f), "{f:?} must trigger fallback");
        }
        // Non-triggers.
        for f in [
            rejected(JobRejectReason::NotGranted),
            rejected(JobRejectReason::ToolchainMissing),
            rejected(JobRejectReason::LimitsExceed),
            rejected(JobRejectReason::SourceMismatch),
        ] {
            assert!(!is_fallback_trigger(&f), "{f:?} must NOT trigger fallback");
        }
    }

    #[test]
    fn fallback_action_returns_none_on_a_non_trigger() {
        assert_eq!(
            fallback_action(
                Fallback::Local,
                None,
                &rejected(JobRejectReason::NotGranted)
            ),
            None
        );
    }

    #[test]
    fn fallback_action_uses_config_fallback_by_default() {
        assert_eq!(
            fallback_action(Fallback::Local, None, &RunFailure::NoRunner),
            Some(FallbackAction::RunLocal)
        );
        assert_eq!(
            fallback_action(Fallback::Wait, None, &RunFailure::NoRunner),
            Some(FallbackAction::Wait)
        );
        assert_eq!(
            fallback_action(Fallback::Fail, None, &RunFailure::NoRunner),
            Some(FallbackAction::Fail)
        );
    }

    #[test]
    fn fallback_action_cli_override_wins() {
        assert_eq!(
            fallback_action(Fallback::Local, Some(Fallback::Fail), &RunFailure::NoRunner),
            Some(FallbackAction::Fail)
        );
        assert_eq!(
            fallback_action(Fallback::Fail, Some(Fallback::Local), &RunFailure::NoRunner),
            Some(FallbackAction::RunLocal)
        );
    }

    #[test]
    fn outcome_exit_code_passes_through_job_code() {
        let accepted = JobOutcome::Accepted(JobResult {
            job_id: vec![1],
            exit_code: 3,
            attestation: Vec::new(),
        });
        assert_eq!(outcome_exit_code(&accepted), 3);
        // Exit code 0 passes through unchanged (a real success).
        let ok = JobOutcome::Accepted(JobResult {
            job_id: vec![1],
            exit_code: 0,
            attestation: Vec::new(),
        });
        assert_eq!(outcome_exit_code(&ok), 0);
    }

    #[test]
    fn outcome_exit_code_is_254_on_reject() {
        let rejected = JobOutcome::Rejected(JobRejectReason::BusyTimeout);
        assert_eq!(outcome_exit_code(&rejected), RUNNER_FAILURE_EXIT);
        assert_eq!(RUNNER_FAILURE_EXIT, 254);
    }

    #[test]
    fn reason_lines_are_human_readable() {
        assert_eq!(RunFailure::NoRunner.reason(), "no runner reachable");
        assert_eq!(
            rejected(JobRejectReason::OnBattery).reason(),
            "runner rejected: on-battery"
        );
    }
}
