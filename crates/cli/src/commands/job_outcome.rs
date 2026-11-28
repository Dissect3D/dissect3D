//! Command-promise exit code and envelope mapping for job observation outcomes.

use crate::commands::observe::ObserveEnd;
use crate::output::{CommandOutcome, ErrorInfo};
use dissect3d_api::{ExecutionJobSnapshot, ExecutionJobState, JobId};

/// The command promise determines how terminal job states map to exit codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Promise {
    Watch,
    Wait,
    Run,
}

pub(crate) fn exit_code(promise: Promise, end: &ObserveEnd) -> i32 {
    match end {
        ObserveEnd::Terminal(snapshot) => match promise {
            Promise::Watch => 0,
            Promise::Wait | Promise::Run => match snapshot.summary.state {
                ExecutionJobState::Succeeded => 0,
                ExecutionJobState::Failed => 10,
                ExecutionJobState::Partial => 11,
                ExecutionJobState::Canceled => 12,
                ExecutionJobState::Interrupted => 13,
                _ => 19,
            },
        },
        ObserveEnd::TimedOut { .. } => 14,
        ObserveEnd::Interrupted { .. } => 18,
        ObserveEnd::ReadsExhausted { .. } => 3,
        ObserveEnd::NotFound(_) => 19,
    }
}

pub(crate) fn render_outcome(command: &str, promise: Promise, end: &ObserveEnd) -> CommandOutcome {
    let accepted = matches!(promise, Promise::Run).then_some(serde_json::Value::Bool(true));
    match end {
        ObserveEnd::Terminal(snapshot) => {
            if exit_code(promise, end) == 0 {
                let mut outcome = snapshot_success(command, snapshot);
                if matches!(promise, Promise::Run) {
                    // Foreground run preserves accepted: true on terminal outcomes.
                    outcome = outcome.with_accepted(serde_json::Value::Bool(true));
                }
                return outcome;
            }
            let (category, message) = match snapshot.summary.state {
                ExecutionJobState::Failed => ("job_failed", "Job ended in failed state"),
                ExecutionJobState::Partial => {
                    ("job_partial", "Job ended with a declared partial outcome")
                }
                ExecutionJobState::Canceled => ("job_canceled", "Job was canceled"),
                ExecutionJobState::Interrupted => ("job_interrupted", "Job was interrupted"),
                _ => ("job_failed", "Job ended in an unexpected state"),
            };
            failure_with_snapshot(
                command,
                ErrorInfo::new(category, message),
                accepted,
                &snapshot.summary.job_id,
                Some(snapshot),
                Vec::new(),
            )
        }
        ObserveEnd::TimedOut { job_id, last } => {
            let warnings = stale_warnings(last.is_some());
            failure_with_snapshot(
                command,
                ErrorInfo::new(
                    "observation_timeout",
                    "Observation timed out; the job remains engine-owned and was not canceled",
                ),
                accepted,
                job_id,
                last.as_deref(),
                warnings,
            )
        }
        ObserveEnd::Interrupted { job_id, last } => {
            let warnings = stale_warnings(last.is_some());
            failure_with_snapshot(
                command,
                ErrorInfo::new(
                    "interrupted",
                    "Observation interrupted; the job remains engine-owned and was not canceled",
                ),
                accepted,
                job_id,
                last.as_deref(),
                warnings,
            )
        }
        ObserveEnd::ReadsExhausted { job_id, last } => {
            let warnings = stale_warnings(last.is_some());
            failure_with_snapshot(
                command,
                ErrorInfo::new(
                    "engine_unavailable",
                    "Engine became unavailable while observing job; last known state may be stale",
                ),
                accepted,
                job_id,
                last.as_deref(),
                warnings,
            )
        }
        ObserveEnd::NotFound(job_id) => CommandOutcome::failure_with_context(
            command,
            ErrorInfo::new("not_found", "The requested job was not found"),
            accepted,
            None,
            Some(serde_json::json!({ "job_id": job_id })),
        ),
    }
}

fn stale_warnings(has_snapshot: bool) -> Vec<String> {
    if has_snapshot {
        vec!["last_known_state_may_be_stale".to_owned()]
    } else {
        Vec::new()
    }
}

fn snapshot_success(command: &str, snapshot: &ExecutionJobSnapshot) -> CommandOutcome {
    match serde_json::value::to_raw_value(snapshot) {
        Ok(raw) => CommandOutcome::success_raw(command, raw),
        Err(_) => CommandOutcome::success(
            command,
            serde_json::json!({ "job_id": snapshot.summary.job_id }),
        ),
    }
}

fn failure_with_snapshot(
    command: &str,
    error: ErrorInfo,
    accepted: Option<serde_json::Value>,
    job_id: &JobId,
    snapshot: Option<&ExecutionJobSnapshot>,
    warnings: Vec<String>,
) -> CommandOutcome {
    if let Some(snapshot) = snapshot
        && let Ok(raw) = serde_json::value::to_raw_value(snapshot)
    {
        return CommandOutcome::failure_with_context(command, error, accepted, None, None)
            .with_raw_data(Some(raw))
            .with_warnings(warnings);
    }
    CommandOutcome::failure_with_context(
        command,
        error,
        accepted,
        None,
        Some(serde_json::json!({ "job_id": job_id })),
    )
    .with_warnings(warnings)
}

#[cfg(test)]
#[path = "job_outcome_tests.rs"]
mod tests;
