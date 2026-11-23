//! WE-003 job control over the controller (WE-P06/4). Cancellation commits
//! durable intent in the Store first, then delivers it to the registered
//! attempt; the response is the current snapshot, never a promise that
//! termination has happened. A queued job is canceled without launch; a
//! terminal job is never reopened. Retry acceptance stays with the submission
//! service; the route slice (WE-P06/5-/7) wakes the controller after it.
use super::controller::ExecutionHandle;
use super::types::StopIntent;
use crate::submission::SubmissionError;
use crate::{AuthContext, CoreError, Store};
use dissect3d_api::{CancelEffect, CancelResponse, ErrorCode, ExecutionJobSnapshot, JobId};
use std::sync::Arc;

/// The Store operations cancellation needs.
pub(crate) trait ControlStore: Send + Sync + 'static {
    fn cancel(&self, auth: AuthContext, job: JobId) -> Result<&'static str, CoreError>;
    fn snapshot(&self, auth: AuthContext, job: JobId) -> Result<ExecutionJobSnapshot, CoreError>;
    /// One consistent read without the currency confirmation.
    fn committed_snapshot(
        &self,
        auth: AuthContext,
        job: JobId,
    ) -> Result<ExecutionJobSnapshot, CoreError>;
}
impl ControlStore for Store {
    fn cancel(&self, auth: AuthContext, job: JobId) -> Result<&'static str, CoreError> {
        self.cancel_execution_job(auth, job)
    }
    fn snapshot(&self, auth: AuthContext, job: JobId) -> Result<ExecutionJobSnapshot, CoreError> {
        self.execution_job_snapshot(auth, job)
    }
    fn committed_snapshot(
        &self,
        auth: AuthContext,
        job: JobId,
    ) -> Result<ExecutionJobSnapshot, CoreError> {
        self.execution_job_snapshot_unconfirmed(auth, job)
    }
}

/// Further snapshot reads after a committed cancel while the job keeps
/// changing; each read itself confirms up to four revisions.
const SNAPSHOT_REREADS: usize = 8;

fn problem(error: CoreError) -> SubmissionError {
    match error {
        // Another creator's job is indistinguishable from a missing one.
        CoreError::NotFound => ErrorCode::NotFound.into(),
        other => other.into(),
    }
}

/// Cancel one job for its creator. Repeat-safe: a repeated request returns
/// the current effect and launches or reopens nothing.
pub(crate) async fn cancel<S: ControlStore>(
    store: Arc<S>,
    handle: &ExecutionHandle,
    auth: AuthContext,
    job: JobId,
) -> Result<CancelResponse, SubmissionError> {
    let writer = Arc::clone(&store);
    let (request_auth, request_job) = (auth.clone(), job.clone());
    let effect = tokio::task::spawn_blocking(move || writer.cancel(request_auth, request_job))
        .await
        .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
        .map_err(problem)?;
    let cancel_effect = match effect {
        "requested" => CancelEffect::Requested,
        "canceled_before_dispatch" => CancelEffect::CanceledBeforeDispatch,
        "already_terminal" => CancelEffect::AlreadyTerminal,
        _ => return Err(ErrorCode::StoreUnavailable.into()),
    };
    if cancel_effect == CancelEffect::Requested {
        // Committed: deliver it. An attempt not yet registered reads the
        // committed intent itself before launch.
        handle.signal(&job, StopIntent::UserCancel);
    }
    // The cancel is committed: never answer a transient read conflict with an
    // error. `Busy` only means the snapshot kept changing while it was read
    // (a running attempt reporting progress), so read again, boundedly, and
    // then answer from one consistent read that skips the currency check. A
    // remaining failure (revocation in between, accepted 2026-11-24; a store
    // fault or a saturated queue) is reported truthfully; cancellation is
    // repeat-safe (WE-003).
    let job_snapshot = tokio::task::spawn_blocking(move || {
        let mut read = store.snapshot(auth.clone(), job.clone());
        for _ in 0..SNAPSHOT_REREADS {
            if !matches!(read, Err(CoreError::Busy)) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
            read = store.snapshot(auth.clone(), job.clone());
        }
        match read {
            Err(CoreError::Busy) => store.committed_snapshot(auth, job),
            read => read,
        }
    })
    .await
    .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?
    .map_err(problem)?;
    Ok(CancelResponse {
        job_snapshot,
        cancel_effect,
    })
}

/// The `job_execution` capability an execution host advertises (WE-001),
/// with the effective values this engine enforces; none is raised silently.
pub(crate) fn capability() -> dissect3d_api::ExecutionCapability {
    use super::types::SupervisionLimits;
    use crate::store::admission::AcceptanceLimits;
    use crate::store::execution::EVENT_RETENTION;
    use crate::worker_protocol::{BUFFERED_FRAMES_MAX, DIAGNOSTIC_BYTES_MAX, FRAME_BYTES_MAX};
    let ms = |d: std::time::Duration| d.as_millis() as u64;
    let c = SupervisionLimits::CONTRACT;
    let limits = [
        ("execution_timeout_ms_max", 86_400_000),
        (
            "active_attempts_max",
            super::controller::ExecutionLimits::CONTROLLED.max_active as u64,
        ),
        ("queued_jobs_max", AcceptanceLimits::default().queued as u64),
        ("job_event_revisions_max", EVENT_RETENTION.revisions as u64),
        ("job_event_history_bytes_max", EVENT_RETENTION.bytes as u64),
        ("worker_control_frame_bytes_max", FRAME_BYTES_MAX as u64),
        (
            "worker_control_frames_buffered_max",
            BUFFERED_FRAMES_MAX as u64,
        ),
        ("worker_diagnostic_bytes_max", DIAGNOSTIC_BYTES_MAX as u64),
        ("worker_launch_ms", ms(c.launch)),
        ("worker_handshake_ms", ms(c.handshake)),
        ("worker_load_ms", ms(c.load)),
        ("worker_cooperative_cancel_ms", ms(c.cooperative_cancel)),
        ("worker_termination_ms", ms(c.termination)),
        ("worker_shutdown_ms", ms(c.shutdown)),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    dissect3d_api::ExecutionCapability {
        contract_version: dissect3d_api::JOB_CONTRACT.to_owned(),
        dispatch_enabled: true,
        operations: [
            "inputs.create",
            "jobs.submit",
            "jobs.list",
            "jobs.show",
            "jobs.cancel",
            "jobs.retry",
        ]
        .map(str::to_owned)
        .to_vec(),
        limits,
        required_features: vec![dissect3d_api::EXECUTION_FEATURE.to_owned()],
    }
}
