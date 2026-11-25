//! Single-threaded SQLite authority with a bounded typed command queue.
//!
//! The actor is the sole owner of both the SQLite connection and authority
//! lease. Callers submit typed requests through a finite queue, so database
//! ordering is explicit and overload is returned as `Busy` instead of growing
//! unbounded work in memory.

use crate::{AuthContext, CorePolicy, VerifiedEnrollment, credentials::GrantPolicy};
use dissect3d_api::{
    ClientId, EnrollmentReceipt, IdempotencyKey, InstallationId, InstanceId, OperationId,
    OperationSnapshot, OperationState, OperationTarget, RevocationReceipt, TimestampMs,
    TokenDigest,
};
#[cfg(unix)]
use dissect3d_api::{ContentDigest, InputId, InputIdentity, InputReceipt};
#[cfg(unix)]
use dissect3d_platform::DurableFile;
use dissect3d_platform::{
    AuthorityLease, OwnedRoot, PlatformError, RelativePath, current_owner_identity,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, limits,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
pub(crate) mod inputs;
#[cfg(unix)]
use crate::domain::input_policy::{
    MAX_INPUT_BYTES, MAX_INPUT_ROWS, MAX_STAGING_BYTES, MAX_UPLOADS, STORAGE_FREE_RESERVE_BYTES,
    UPLOAD_METADATA_RESERVE_BYTES, UPLOAD_TTL_MS,
};
#[cfg(unix)]
use inputs::{abandon_upload, complete_upload, reserve_upload};
#[cfg(unix)]
pub(crate) mod admission;
#[cfg(unix)]
pub(crate) mod jobs;
#[cfg(unix)]
pub(crate) mod retry;
#[cfg(unix)]
pub(crate) mod submission;

#[allow(
    dead_code,
    reason = "WE-P04/07 report attempt cleanup through this seam; dispatch stays inactive"
)]
pub(crate) mod cleanup;
#[allow(
    dead_code,
    reason = "WE-P04/06 integrate the private lifecycle seam; dispatch stays inactive"
)]
pub(crate) mod execution;
#[cfg(unix)]
#[allow(dead_code, reason = "WE-P06 owns public execution read activation")]
mod execution_reads;
mod execution_schema;
#[allow(
    dead_code,
    reason = "WE-P04/06 compose supervised finalization; dispatch stays inactive"
)]
pub(crate) mod finalize;
#[allow(
    dead_code,
    reason = "WE-P06 composes the supervisor's launch ledger; dispatch stays inactive"
)]
pub(crate) mod launch_identity;
pub(crate) mod reauthorization;
// WE-P07/4 restart reconciliation reads; only the execution host uses them.
#[cfg_attr(not(all(unix, feature = "test-support")), allow(dead_code))]
pub(crate) mod recovery;
#[allow(
    dead_code,
    reason = "RP-P03/RP-P04/WE-P06 compose result metadata; publication stays inactive"
)]
pub(crate) mod results;
#[allow(
    dead_code,
    reason = "WE-P06 drives the publication commit; publication stays inactive"
)]
pub(crate) mod results_commit;
#[cfg(unix)]
pub(crate) mod results_reads;
mod results_schema;
use execution_schema::add_execution_tables;
use results_schema::add_result_tables;

mod actor;
mod credentials;
mod ids;
mod schema;
mod shutdown;
use actor::*;
use credentials::*;
pub(crate) use ids::random_id;
use ids::*;
use schema::*;
use shutdown::*;

const APPLICATION_ID: i64 = 0x4433_4431;
const SCHEMA_VERSION: i64 = 8;
const DATABASE_NAME: &str = "metadata.sqlite3";
// `recovery/metadata-upgrade.sqlite3` is a legacy artifact and is never opened
// or replaced by this migration. Keep the v3 pre-upgrade image distinct.
const RECOVERY_BACKUP: &str = "recovery/metadata-v3-upgrade.sqlite3";
const RECOVERY_BACKUP_V4: &str = "recovery/metadata-v4-upgrade.sqlite3";
const RECOVERY_BACKUP_V5: &str = "recovery/metadata-v5-upgrade.sqlite3";
// Result publication (RP-P02/1). Earlier images are never replaced.
const RECOVERY_BACKUP_V8: &str = "recovery/metadata-v8-upgrade.sqlite3";
pub(crate) const RECOVERY_BACKUP_LIMIT_BYTES: i64 = 268_435_456;
const RECOVERY_BACKUP_FREE_SPACE_FLOOR_BYTES: u64 = 1_073_741_824;
pub(crate) const MAX_CORE_OPERATION_ROWS: i64 = 16_384;
pub(crate) const MAX_CREDENTIAL_ROWS: i64 = 1_024;
#[cfg(unix)]
const MAX_CLEANUP_BATCH: usize = 64;
/// Internal committed shutdown facts before HTTP adapts them to OperationReceipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShutdownAcceptance {
    pub(crate) api_version: String,
    pub(crate) operation_id: OperationId,
    pub(crate) instance_id: InstanceId,
    pub(crate) state: OperationState,
    pub(crate) accepted_at_ms: TimestampMs,
    pub(crate) replayed: bool,
}

/// Actor-issued authority to create one generated input identity.
#[cfg(unix)]
pub(crate) struct UploadReservation {
    pub(crate) reservation_id: String,
    pub(crate) input_id: InputId,
    pub(crate) declared_length: u64,
    pub(crate) media_type: String,
    pub(crate) lease: Arc<()>,
}

/// Native publication witness and engine-computed digest offered for commit.
#[cfg(unix)]
pub(crate) struct DurableInput {
    pub(crate) file: DurableFile,
    pub(crate) sha256: [u8; 32],
}

/// Safe persistence and authority error categories.
///
/// Variants intentionally omit SQLite and operating-system diagnostics; those
/// details stay local to the engine and cannot leak through the service API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreError {
    InvalidStore,
    StoreIncompatible,
    StoreUnavailable,
    Busy,
    Conflict,
    Unauthorized,
    NotFound,
    LimitReached,
    /// A finite input-policy limit, identified by its public safe key.
    CapacityExceeded(&'static str),
    Platform(PlatformError),
}

/// Stable installation identity and this process's service session identity.
/// The installation survives restarts; the instance identifies this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    pub installation_id: InstallationId,
    pub instance_id: InstanceId,
}

/// Bounded handle to the only thread allowed to own SQLite and the lease.
/// Dropping the handle waits for the actor to close SQLite before releasing
/// authority, preventing another process from opening the store too early.
pub struct Store {
    sender: SyncSender<Command>,
    thread: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    #[cfg(unix)]
    preparation_root: Arc<OwnedRoot>,
    /// Submission/retry admission only (`bounded_admission`). Execution reads
    /// use the bounded actor queue and never take a slot.
    #[cfg(unix)]
    submission_preparation: admission::PreparationGate,
}

impl Store {
    /// Start the store actor, transferring the root and sole authority lease.
    pub fn open(
        root: OwnedRoot,
        lease: AuthorityLease,
        policy: &CorePolicy,
    ) -> Result<Self, CoreError> {
        Self::open_with_shutdown(root, lease, policy, None)
    }

    /// Start the store actor with an engine-owned shutdown coordinator wakeup.
    ///
    /// The actor emits this only after a queued shutdown is committed, so
    /// client-task cancellation cannot strand a durable intent.
    pub(crate) fn open_with_shutdown(
        root: OwnedRoot,
        lease: AuthorityLease,
        policy: &CorePolicy,
        shutdown: Option<tokio::sync::mpsc::UnboundedSender<Instant>>,
    ) -> Result<Self, CoreError> {
        // Startup is acknowledged only after the database has been opened,
        // validated, and initialized; callers never receive a half-ready store.
        let (sender, receiver) = mpsc::sync_channel(policy.queue_capacity);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let actor_stopping = stopping.clone();
        let root = Arc::new(root);
        #[cfg(unix)]
        let preparation_root = root.clone();
        #[cfg(unix)]
        let preparation_capacity = policy.queue_capacity;
        let policy = policy.clone();
        let thread = thread::Builder::new()
            .name("dissect3d-store".to_owned())
            .spawn(move || {
                actor(
                    root,
                    lease,
                    policy,
                    receiver,
                    ready_tx,
                    shutdown,
                    actor_stopping,
                )
            })
            .map_err(|_| CoreError::StoreUnavailable)?;
        match ready_rx.recv().map_err(|_| CoreError::StoreUnavailable)? {
            Ok(()) => Ok(Self {
                sender,
                thread: Some(thread),
                stopping,
                #[cfg(unix)]
                preparation_root,
                #[cfg(unix)]
                submission_preparation: admission::PreparationGate::new(preparation_capacity),
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    /// Read the durable installation and current instance identities.
    pub fn identity(&self) -> Result<StoreIdentity, CoreError> {
        self.request(Command::Identity)
    }

    /// Durably enroll a natively verified client and return the exact replay receipt.
    pub fn enroll(&self, enrollment: VerifiedEnrollment) -> Result<EnrollmentReceipt, CoreError> {
        self.request(|response| Command::Enroll(enrollment, response))
    }

    /// Authenticate a client by comparing its fixed-size token digest in constant time.
    pub fn authenticate(
        &self,
        client_id: ClientId,
        token_digest: TokenDigest,
    ) -> Result<AuthContext, CoreError> {
        self.request(|response| Command::Authenticate(client_id, token_digest, response))
    }

    /// Authenticate and snapshot service identity in one serialized actor turn.
    pub(crate) fn authorize_snapshot(
        &self,
        client_id: ClientId,
        token_digest: TokenDigest,
    ) -> Result<(StoreIdentity, AuthContext), CoreError> {
        self.request(|response| Command::Snapshot(client_id, token_digest, response))
    }

    /// Revoke only the authenticated client's own credential.
    pub fn revoke_self(&self, context: AuthContext) -> Result<RevocationReceipt, CoreError> {
        self.request(|response| Command::Revoke(context, response))
    }

    pub(crate) fn request_shutdown(
        &self,
        context: AuthContext,
        instance_id: InstanceId,
        key: IdempotencyKey,
    ) -> Result<ShutdownAcceptance, CoreError> {
        self.request(|response| Command::Shutdown(context, instance_id, key, response))
    }

    /// Read an operation only after rechecking this creator's active grant.
    pub(crate) fn show_operation(
        &self,
        context: AuthContext,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, CoreError> {
        self.request(|response| Command::ShowOperation(context, operation_id, response))
    }

    #[cfg(unix)]
    pub(crate) fn reserve_upload(
        &self,
        context: AuthContext,
        declared_length: u64,
        media_type: String,
        available_space_bytes: u64,
    ) -> Result<UploadReservation, CoreError> {
        self.request(|response| {
            Command::ReserveUpload(
                context,
                declared_length,
                media_type,
                available_space_bytes,
                response,
            )
        })
    }

    #[cfg(unix)]
    pub(crate) fn complete_upload(
        &self,
        context: AuthContext,
        reservation: UploadReservation,
        input: DurableInput,
    ) -> Result<InputReceipt, CoreError> {
        self.request(|response| Command::CompleteUpload(context, reservation, input, response))
    }

    /// Release an incomplete reservation after its staging file has been
    /// durably removed. If cleanup cannot prove deletion, keep its charge.
    #[cfg(unix)]
    pub(crate) fn abandon_upload(&self, reservation_id: String) -> Result<(), CoreError> {
        self.request(|response| Command::AbandonUpload(reservation_id, response))
    }

    #[cfg(unix)]
    pub(crate) fn pin_verified_inputs(
        &self,
        context: AuthContext,
        input_ids: Vec<InputId>,
    ) -> Result<inputs::PinnedInputSet, CoreError> {
        self.request(|response| Command::PinVerifiedInputs(context, input_ids, response))
    }

    #[cfg(unix)]
    pub(crate) fn claim_input_cleanup(&self) -> Result<Vec<inputs::InputCleanupClaim>, CoreError> {
        self.request(|response| Command::ClaimInputCleanup(None, response))
    }

    #[cfg(all(unix, test))]
    pub(crate) fn claim_input_cleanup_at(
        &self,
        requested_time_ms: i64,
    ) -> Result<Vec<inputs::InputCleanupClaim>, CoreError> {
        self.request(|response| Command::ClaimInputCleanup(Some(requested_time_ms), response))
    }

    #[cfg(unix)]
    pub(crate) fn confirm_input_cleanup(
        &self,
        claim: inputs::InputCleanupClaim,
    ) -> Result<(), CoreError> {
        self.request(|response| Command::ConfirmInputCleanup(claim, response))
    }

    #[cfg(unix)]
    pub(crate) fn input_file_known(&self, input_id: InputId) -> Result<bool, CoreError> {
        self.request(|response| Command::InputFileKnown(input_id, response))
    }

    #[cfg(all(unix, test, feature = "test-support"))]
    pub(crate) fn fail_next_job_commit(&self) -> Result<(), CoreError> {
        self.request(Command::FailNextJobCommit)
    }
    #[cfg(unix)]
    pub(crate) fn probe_job_binding(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::JobRequest,
    ) -> Result<Option<dissect3d_api::AcceptanceReceipt>, crate::domain::SubmissionError> {
        self.prepare_submission(
            auth,
            key,
            crate::submission::equivalence::SubmittedJobRequest::Legacy(request),
            None,
        )
    }

    #[cfg(unix)]
    pub(crate) fn accept_job(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::JobRequest,
        candidate: crate::submission::admission::AdmissionCandidate,
    ) -> Result<dissect3d_api::AcceptanceReceipt, crate::domain::SubmissionError> {
        self.prepare_submission(
            auth,
            key,
            crate::submission::equivalence::SubmittedJobRequest::Legacy(request),
            Some(candidate),
        )?
        .ok_or_else(|| dissect3d_api::ErrorCode::StoreUnavailable.into())
    }

    #[cfg(unix)]
    pub(crate) fn probe_execution_binding(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::ExecutionJobRequest,
    ) -> Result<Option<dissect3d_api::AcceptanceReceipt>, crate::domain::SubmissionError> {
        dissect3d_api::encode_execution_request(&request).map_err(|_| {
            crate::domain::SubmissionError::from(dissect3d_api::ErrorCode::InvalidRequest)
        })?;
        self.prepare_submission(
            auth,
            key,
            crate::submission::equivalence::SubmittedJobRequest::Execution(request),
            None,
        )
    }
    #[cfg(unix)]
    pub(crate) fn accept_execution_job(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::ExecutionJobRequest,
        candidate: crate::submission::admission::AdmissionCandidate,
    ) -> Result<dissect3d_api::AcceptanceReceipt, crate::domain::SubmissionError> {
        dissect3d_api::encode_execution_request(&request).map_err(|_| {
            crate::domain::SubmissionError::from(dissect3d_api::ErrorCode::InvalidRequest)
        })?;
        self.prepare_submission(
            auth,
            key,
            crate::submission::equivalence::SubmittedJobRequest::Execution(request),
            Some(candidate),
        )?
        .ok_or_else(|| dissect3d_api::ErrorCode::StoreUnavailable.into())
    }
    #[cfg(all(unix, test, feature = "test-support"))]
    pub(crate) fn set_test_job_limits(&self, limits: admission::AcceptanceLimits) {
        self.request(|reply| Command::JobLimits(limits, reply))
            .unwrap();
    }

    #[cfg(all(unix, test, feature = "test-support"))]
    pub(crate) fn accept_job_without_reply(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::JobRequest,
        candidate: crate::submission::admission::AdmissionCandidate,
    ) {
        let request = crate::submission::equivalence::SubmittedJobRequest::Legacy(request);
        let state = self
            .request(|reply| {
                Command::ReadSubmission(auth.clone(), key.clone(), request.clone(), reply)
            })
            .unwrap();
        let prepared = submission::prepare(
            &self.preparation_root,
            &auth,
            &key,
            &request,
            Some(&candidate),
            state,
        );
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(Command::FinishSubmission(
                auth,
                key,
                request,
                Some(Arc::new(candidate)),
                Box::new(prepared),
                reply,
            ))
            .ok()
            .unwrap();
        drop(receiver);
    }

    #[cfg(unix)]
    fn prepare_submission(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: crate::submission::equivalence::SubmittedJobRequest,
        candidate: Option<crate::submission::admission::AdmissionCandidate>,
    ) -> Result<Option<dissect3d_api::AcceptanceReceipt>, crate::domain::SubmissionError> {
        // Candidate ownership must survive stale preparation. A finish command
        // borrows it through an Arc, including after its reply is abandoned.
        let candidate = candidate.map(Arc::new);
        self.bounded_admission(
            || {
                self.request(|reply| {
                    Command::ReadSubmission(auth.clone(), key.clone(), request.clone(), reply)
                })
            },
            |state| {
                submission::prepare(
                    &self.preparation_root,
                    &auth,
                    &key,
                    &request,
                    candidate.as_deref(),
                    state,
                )
            },
            |prepared| {
                self.request(|reply| {
                    Command::FinishSubmission(
                        auth.clone(),
                        key.clone(),
                        request.clone(),
                        candidate.clone(),
                        Box::new(prepared),
                        reply,
                    )
                })
            },
        )
    }

    /// WE-003 exact linked retry of a terminal source this client created.
    /// WE-P06 owns the public route; dispatch of the new job stays inactive.
    #[cfg(unix)]
    pub(crate) fn retry_job(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        source: dissect3d_api::JobId,
        prerequisites: retry::RetryPrerequisites,
    ) -> Result<dissect3d_api::ExecutionAcceptance, crate::domain::SubmissionError> {
        self.bounded_admission(
            || {
                self.request(|reply| {
                    Command::ReadRetry(auth.clone(), key.clone(), source.clone(), reply)
                })
            },
            |state| {
                retry::prepare_retry(
                    &self.preparation_root,
                    &auth,
                    &key,
                    &source,
                    &prerequisites,
                    state,
                )
            },
            |prepared| {
                self.request(|reply| {
                    Command::FinishRetry(
                        auth.clone(),
                        key.clone(),
                        source.clone(),
                        Box::new(prepared),
                        reply,
                    )
                })
            },
        )
    }

    /// Bounded caller preparation: read a SQL snapshot on the actor, prepare on
    /// this blocking caller, and let the actor make the final decision. Stale
    /// work (`None`) is retried from SQL at most four times, then `Busy`; it
    /// cannot authorize, reserve bytes, or overwrite a competing binding.
    #[cfg(unix)]
    fn bounded_admission<S, P, T>(
        &self,
        read: impl Fn() -> Result<S, crate::domain::SubmissionError>,
        prepare: impl Fn(S) -> P,
        finish: impl Fn(P) -> Result<Option<T>, crate::domain::SubmissionError>,
    ) -> Result<T, crate::domain::SubmissionError> {
        let _permit = self.submission_preparation.acquire()?;
        for _ in 0..4 {
            if let Some(outcome) = finish(prepare(read()?))? {
                return Ok(outcome);
            }
        }
        Err(CoreError::Busy.into())
    }

    #[cfg(unix)]
    pub(crate) fn show_job(
        &self,
        auth: AuthContext,
        id: dissect3d_api::JobId,
    ) -> Result<dissect3d_api::JobSnapshot, crate::domain::SubmissionError> {
        self.request(|reply| Command::ShowJob(auth, id, reply))
    }
    #[cfg(unix)]
    pub(crate) fn list_jobs(
        &self,
        auth: AuthContext,
        query: dissect3d_api::JobsQuery,
    ) -> Result<dissect3d_api::JobPage, crate::domain::SubmissionError> {
        self.request(|reply| Command::ListJobs(auth, query, reply))
    }
    #[cfg(unix)]
    pub(crate) fn job_audit_batch(
        &self,
        after: String,
    ) -> Result<Vec<jobs::AuditEntry>, crate::domain::SubmissionError> {
        self.request(|reply| Command::JobAuditBatch(after, reply))
    }
    #[cfg(unix)]
    pub(crate) fn mark_job_input_fault(
        &self,
        id: InputId,
    ) -> Result<(), crate::domain::SubmissionError> {
        self.request(|reply| Command::MarkJobInputFault(id, reply))
    }
    pub(crate) fn complete_shutdown(&self, instance_id: InstanceId) -> Result<(), CoreError> {
        self.request(|response| Command::CompleteShutdown(instance_id, response))
    }

    pub(crate) fn signal_shutdown(
        &self,
        instance_id: InstanceId,
        timeout_ms: u32,
    ) -> Result<Instant, CoreError> {
        self.request(|response| Command::SignalShutdown(instance_id, timeout_ms, response))
    }

    pub(crate) fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn limit_database_pages_to_current_plus_one(&self) -> Result<(), CoreError> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.sender
            .try_send(Command::LimitDatabasePages(response_tx))
            .map_err(|_| CoreError::Busy)?;
        response_rx
            .recv()
            .map_err(|_| CoreError::StoreUnavailable)?
    }

    #[cfg(test)]
    fn fail_next_shutdown_commit(&self) -> Result<(), CoreError> {
        self.sender
            .try_send(Command::FailNextShutdownCommit)
            .map_err(|_| CoreError::Busy)
    }

    #[cfg(test)]
    fn seed_operation_history(&self, count: usize) -> Result<(), CoreError> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        self.sender
            .try_send(Command::SeedOperationHistory(count, response_tx))
            .map_err(|_| CoreError::Busy)?;
        response_rx
            .recv()
            .map_err(|_| CoreError::StoreUnavailable)?
    }

    /// Send one typed command and wait for its reply, for any Store error type.
    fn request<T, E: From<CoreError>>(
        &self,
        command: impl FnOnce(mpsc::SyncSender<Result<T, E>>) -> Command,
    ) -> Result<T, E> {
        // Capacity-one replies make each request self-contained while try_send
        // keeps queue saturation observable instead of blocking producers.
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        match self.sender.try_send(command(response_tx)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(CoreError::Busy.into()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(CoreError::StoreUnavailable.into());
            }
        }
        response_rx
            .recv()
            .map_err(|_| E::from(CoreError::StoreUnavailable))?
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // A blocking send is intentional here: it queues Close behind accepted
        // commands, then join ensures the connection and lease are both gone.
        let _ = self.sender.send(Command::Close);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// SQLite failures map to the safe store category; `?` adapts it to callers' error types.
fn sql<T>(value: rusqlite::Result<T>) -> Result<T, CoreError> {
    value.map_err(|_| CoreError::StoreUnavailable)
}

#[cfg(test)]
#[path = "store/core_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "store/input_cleanup_tests.rs"]
mod input_cleanup_tests;
#[cfg(test)]
#[path = "store/submission_tests.rs"]
mod submission_tests;

#[cfg(all(test, unix))]
mod job_tests;

#[cfg(test)]
#[path = "store/execution_tests.rs"]
mod execution_regressions;

#[cfg(test)]
#[path = "store/commit_latency_probe.rs"]
mod commit_latency_probe;
#[cfg(test)]
#[path = "store/native_authorization_tests.rs"]
mod native_authorization_tests;

#[cfg(all(test, unix, feature = "test-support"))]
mod preparation_tests;
