//! One candidate from confirmed cleanup to exactly one authoritative outcome
//! (RP-P03; RP-001/003, WE-002-WE-005; outcome codes decided 2026-11-23).
//!
//! Order: capture through the retained staging handle, verify the captured
//! input snapshot, validate independently, prepare durably and privately,
//! then ask the Store to commit. Only that commit succeeds a job. Every other
//! path ends the attempt through finalization with the same native cleanup
//! witness:
//! - an attempt deadline passed at any step: `execution_deadline_exceeded`;
//! - the candidate was refused, including by validation's own time bound:
//!   `result_validation_failed`;
//! - engine capture, input integrity, preparation or commit storage failed
//!   with no committed result: `result_storage_failed`;
//! - committed cancellation or the shutdown barrier won: their own
//!   transitions (`canceled`, `interrupted`).
//!
//! An uncertain commit is reconciled by reading the committed result for the
//! attempt. Failure is recorded only once that read proves nothing
//! committed. When neither commit nor finalization can be established, the
//! outcome is `Uncertain` and restart recovery reconciles it; nothing is
//! guessed. The whole sequence runs on one blocking task that owns its
//! inputs, so a caller that stops waiting cancels none of it.
use super::capture::{capture_candidate, verified_input};
use super::storage::{ResultLedger, prepare_publication};
use super::{PublicationError, validate_candidate};
use crate::CoreError;
use crate::execution::types::{AttemptCleanup, AttemptEnd, StopIntent};
use crate::store::cleanup::{AttemptRef, CleanupEvidence};
use crate::store::execution::DispatchRecord;
use crate::store::finalize::{AttemptFinalization, FinalizationReceipt};
use crate::store::results_commit::{
    CommitOutcome, CommitRefusal, PublicationCommit, PublicationReceipt,
};
use crate::worker_protocol::CandidateReport;
use dissect3d_api::InputIdentity;
use dissect3d_platform::{AttemptRoot, OwnedRoot, PrivateInputReader};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Preparation bound for an attempt without an execution deadline. It is a
/// finite engineering default, not a measured capacity claim.
const UNTIMED_PREPARATION_BUDGET: Duration = Duration::from_secs(30);

/// The Store operations publication needs beyond its storage ledger.
pub(crate) trait PublicationStore: ResultLedger {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError>;
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError>;
    fn finalize(&self, finalization: AttemptFinalization)
    -> Result<FinalizationReceipt, CoreError>;
}

impl PublicationStore for crate::Store {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        self.commit_publication(commit)
    }
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        self.publication_for_attempt(attempt_id.to_owned())
    }
    fn finalize(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        self.finalize_attempt(finalization)
    }
}

impl<S: PublicationStore + ?Sized> PublicationStore for Arc<S> {
    fn commit(&self, commit: PublicationCommit) -> Result<CommitOutcome, CoreError> {
        (**self).commit(commit)
    }
    fn committed_for(&self, attempt_id: &str) -> Result<Option<PublicationReceipt>, CoreError> {
        (**self).committed_for(attempt_id)
    }
    fn finalize(
        &self,
        finalization: AttemptFinalization,
    ) -> Result<FinalizationReceipt, CoreError> {
        (**self).finalize(finalization)
    }
}

/// Everything one publication owns: the attempt, its untrusted report, the
/// native cleanup witness, the retained staging folder and a fresh reader
/// of the captured input snapshot.
pub(crate) struct PublishRequest {
    pub(crate) dispatch: DispatchRecord,
    pub(crate) report: CandidateReport,
    pub(crate) cleanup: CleanupEvidence,
    pub(crate) staging: AttemptRoot,
    pub(crate) input: InputIdentity,
    pub(crate) input_reader: PrivateInputReader,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PublishOutcome {
    /// The authoritative commit succeeded the job.
    Published(PublicationReceipt),
    /// The attempt ended through finalization: failed, interrupted, or the
    /// completion of a committed cancellation.
    Ended(FinalizationReceipt),
    /// This instance does not own a running attempt any more (already
    /// terminal, or from an earlier session). Nothing was written.
    NotOwned,
    /// Neither a commit nor a finalization could be established. Evidence
    /// and accounting are retained for restart reconciliation.
    Uncertain,
}

/// Which step refused, so a time-bound refusal is classified truthfully.
#[derive(Clone, Copy)]
enum Step {
    Candidate,
    Storage,
}

fn end_for(error: PublicationError, step: Step, dispatch: &DispatchRecord) -> AttemptEnd {
    use PublicationError as E;
    match error {
        // Only the Store-owned attempt clock makes a deadline failure.
        _ if dispatch.timing.expired() => AttemptEnd::DeadlineExceeded,
        E::InvalidCandidate
        | E::InvalidGeometry
        | E::CopyFidelity
        | E::InvalidManifest
        | E::Limit => AttemptEnd::ResultValidationFailed,
        E::Deadline => match step {
            Step::Candidate => AttemptEnd::ResultValidationFailed,
            Step::Storage => AttemptEnd::ResultStorageFailed,
        },
        // The ledger refused the reservation. Its Conflict covers a committed
        // cancellation, an attempt that already has an allocation, and a
        // failed reservation write alike. Finalization tells them apart: it
        // completes a committed cancellation whatever the end, records this
        // storage failure for running work, and refuses terminal work.
        E::Stale | E::Busy | E::Storage | E::Capacity(_) | E::InputIntegrity => {
            AttemptEnd::ResultStorageFailed
        }
    }
}

fn finalize_with(
    store: &impl PublicationStore,
    dispatch: &DispatchRecord,
    cleanup: CleanupEvidence,
    end: AttemptEnd,
) -> PublishOutcome {
    match store.finalize(AttemptFinalization {
        attempt: AttemptRef::from(dispatch),
        end,
        cleanup: AttemptCleanup::Confirmed(cleanup),
    }) {
        Ok(receipt) => PublishOutcome::Ended(receipt),
        // Already terminal with another outcome, or not this attempt.
        Err(CoreError::Conflict) => PublishOutcome::NotOwned,
        Err(_) => PublishOutcome::Uncertain,
    }
}

/// Run one publication to its outcome on the current (blocking) thread.
pub(crate) fn publish_blocking(
    store: &impl PublicationStore,
    root: &OwnedRoot,
    request: PublishRequest,
) -> PublishOutcome {
    let PublishRequest {
        dispatch,
        report,
        cleanup,
        staging,
        input,
        input_reader,
    } = request;
    if dispatch.timing.expired() {
        return finalize_with(store, &dispatch, cleanup, AttemptEnd::DeadlineExceeded);
    }
    let validated = capture_candidate(&dispatch, &report, &cleanup, &staging)
        .map_err(|e| (e, Step::Candidate))
        .and_then(|closed| {
            let inputs = verified_input(input, input_reader).map_err(|e| (e, Step::Storage))?;
            validate_candidate(&dispatch, &closed, &inputs).map_err(|e| (e, Step::Candidate))
        });
    let validated = match validated {
        Ok(validated) => validated,
        Err((error, step)) => {
            let end = end_for(error, step, &dispatch);
            return finalize_with(store, &dispatch, cleanup, end);
        }
    };
    let deadline = dispatch
        .timing
        .deadline()
        .unwrap_or_else(|| Instant::now() + UNTIMED_PREPARATION_BUDGET);
    let prepared = match prepare_publication(store, root, &validated, deadline) {
        Ok(prepared) => prepared,
        Err(error) => {
            let end = end_for(error, Step::Storage, &dispatch);
            return finalize_with(store, &dispatch, cleanup, end);
        }
    };
    let commit = match prepared.into_commit(&dispatch, cleanup.clone()) {
        Ok(commit) => commit,
        Err(_) => {
            return finalize_with(store, &dispatch, cleanup, AttemptEnd::ResultStorageFailed);
        }
    };
    match store.commit(commit) {
        Ok(CommitOutcome::Committed(receipt)) => PublishOutcome::Published(receipt),
        Ok(CommitOutcome::Refused(refusal)) => {
            let end = match refusal {
                CommitRefusal::Canceled => AttemptEnd::Stopped(StopIntent::UserCancel),
                CommitRefusal::ShutdownBarrier => AttemptEnd::Stopped(StopIntent::EngineShutdown),
                CommitRefusal::DeadlineExpired => AttemptEnd::DeadlineExceeded,
                CommitRefusal::NotPrepared => AttemptEnd::ResultStorageFailed,
                CommitRefusal::NotRunning | CommitRefusal::NotCurrentSession => {
                    return PublishOutcome::NotOwned;
                }
            };
            finalize_with(store, &dispatch, cleanup, end)
        }
        // The transaction refused before COMMIT (identity, witness or store
        // invariant): nothing committed, so this is a storage failure.
        Err(CoreError::Conflict | CoreError::InvalidStore) => {
            finalize_with(store, &dispatch, cleanup, AttemptEnd::ResultStorageFailed)
        }
        // COMMIT may or may not have happened: read before deciding.
        Err(_) => match store.committed_for(&dispatch.attempt_id) {
            Ok(Some(receipt)) => PublishOutcome::Published(receipt),
            Ok(None) => finalize_with(store, &dispatch, cleanup, AttemptEnd::ResultStorageFailed),
            Err(_) => PublishOutcome::Uncertain,
        },
    }
}

/// Publish on a blocking task that owns every input until it finishes.
/// Dropping the returned future stops only the waiting.
pub(crate) async fn publish<S>(
    store: S,
    root: Arc<OwnedRoot>,
    request: PublishRequest,
) -> PublishOutcome
where
    S: PublicationStore + Send + 'static,
{
    tokio::task::spawn_blocking(move || publish_blocking(&store, &root, request))
        .await
        .unwrap_or(PublishOutcome::Uncertain)
}
