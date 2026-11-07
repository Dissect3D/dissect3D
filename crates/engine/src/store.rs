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
use crate::inputs::policy::{
    MAX_INPUT_BYTES, MAX_INPUT_ROWS, MAX_STAGING_BYTES, MAX_UPLOADS, STORAGE_FREE_RESERVE_BYTES,
    UPLOAD_METADATA_RESERVE_BYTES, UPLOAD_TTL_MS,
};
#[cfg(unix)]
use inputs::{abandon_upload, complete_upload, reserve_upload};
#[cfg(unix)]
pub(crate) mod jobs;
#[cfg(unix)]
pub(crate) mod submission;

const APPLICATION_ID: i64 = 0x4433_4431;
const SCHEMA_VERSION: i64 = 6;
const DATABASE_NAME: &str = "metadata.sqlite3";
// `recovery/metadata-upgrade.sqlite3` is a legacy artifact and is never opened
// or replaced by this migration. Keep the v3 pre-upgrade image distinct.
const RECOVERY_BACKUP: &str = "recovery/metadata-v3-upgrade.sqlite3";
const RECOVERY_BACKUP_V4: &str = "recovery/metadata-v4-upgrade.sqlite3";
const RECOVERY_BACKUP_V5: &str = "recovery/metadata-v5-upgrade.sqlite3";
pub(crate) const RECOVERY_BACKUP_LIMIT_BYTES: i64 = 268_435_456;
const RECOVERY_BACKUP_FREE_SPACE_FLOOR_BYTES: u64 = 1_073_741_824;
pub(crate) const MAX_CORE_OPERATION_ROWS: i64 = 16_384;
pub(crate) const MAX_CREDENTIAL_ROWS: i64 = 1_024;
#[cfg(unix)]
const MAX_CLEANUP_BATCH: usize = 64;
fn protected_sqlite_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

fn open_internal_database(path: &Path) -> Result<Connection, CoreError> {
    Connection::open_with_flags(path, protected_sqlite_open_flags())
        .map_err(|_| CoreError::StoreUnavailable)
}
struct ExistingCredential {
    client_id: String,
    enrollment_id: String,
    digest: Vec<u8>,
    grant_policy: String,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
}

type OperationRecord = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<String>,
);

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

enum Command {
    #[cfg(all(test, unix, feature = "test-support"))]
    JobLimits(
        submission::AcceptanceLimits,
        mpsc::SyncSender<Result<(), CoreError>>,
    ),
    Identity(mpsc::SyncSender<Result<StoreIdentity, CoreError>>),
    Enroll(
        VerifiedEnrollment,
        mpsc::SyncSender<Result<EnrollmentReceipt, CoreError>>,
    ),
    Authenticate(
        ClientId,
        TokenDigest,
        mpsc::SyncSender<Result<AuthContext, CoreError>>,
    ),
    Snapshot(
        ClientId,
        TokenDigest,
        mpsc::SyncSender<Result<(StoreIdentity, AuthContext), CoreError>>,
    ),
    Revoke(
        AuthContext,
        mpsc::SyncSender<Result<RevocationReceipt, CoreError>>,
    ),
    Shutdown(
        AuthContext,
        InstanceId,
        IdempotencyKey,
        mpsc::SyncSender<Result<ShutdownAcceptance, CoreError>>,
    ),
    ShowOperation(
        AuthContext,
        OperationId,
        mpsc::SyncSender<Result<OperationSnapshot, CoreError>>,
    ),
    #[cfg(unix)]
    ReserveUpload(
        AuthContext,
        u64,
        String,
        u64,
        mpsc::SyncSender<Result<UploadReservation, CoreError>>,
    ),
    #[cfg(unix)]
    CompleteUpload(
        AuthContext,
        UploadReservation,
        DurableInput,
        mpsc::SyncSender<Result<InputReceipt, CoreError>>,
    ),
    #[cfg(unix)]
    AbandonUpload(String, mpsc::SyncSender<Result<(), CoreError>>),
    #[cfg(unix)]
    PinVerifiedInputs(
        AuthContext,
        Vec<InputId>,
        mpsc::SyncSender<Result<inputs::PinnedInputSet, CoreError>>,
    ),
    #[cfg(unix)]
    ClaimInputCleanup(
        Option<i64>,
        mpsc::SyncSender<Result<Vec<inputs::InputCleanupClaim>, CoreError>>,
    ),
    #[cfg(unix)]
    ConfirmInputCleanup(
        inputs::InputCleanupClaim,
        mpsc::SyncSender<Result<(), CoreError>>,
    ),
    #[cfg(unix)]
    InputFileKnown(InputId, mpsc::SyncSender<Result<bool, CoreError>>),
    #[cfg(unix)]
    ProbeJobBinding(
        AuthContext,
        IdempotencyKey,
        dissect3d_api::JobRequest,
        mpsc::SyncSender<
            Result<Option<dissect3d_api::AcceptanceReceipt>, crate::submission::SubmissionError>,
        >,
    ),
    #[cfg(unix)]
    AcceptJob(
        AuthContext,
        IdempotencyKey,
        dissect3d_api::JobRequest,
        Box<crate::submission::admission::AdmissionCandidate>,
        mpsc::SyncSender<
            Result<dissect3d_api::AcceptanceReceipt, crate::submission::SubmissionError>,
        >,
    ),
    #[cfg(unix)]
    ShowJob(
        AuthContext,
        dissect3d_api::JobId,
        mpsc::SyncSender<Result<dissect3d_api::JobSnapshot, crate::submission::SubmissionError>>,
    ),
    #[cfg(unix)]
    ListJobs(
        AuthContext,
        dissect3d_api::JobsQuery,
        mpsc::SyncSender<Result<dissect3d_api::JobPage, crate::submission::SubmissionError>>,
    ),
    #[cfg(unix)]
    JobAuditBatch(
        String,
        mpsc::SyncSender<Result<Vec<jobs::AuditEntry>, crate::submission::SubmissionError>>,
    ),
    #[cfg(unix)]
    MarkJobInputFault(
        InputId,
        mpsc::SyncSender<Result<(), crate::submission::SubmissionError>>,
    ),
    CompleteShutdown(InstanceId, mpsc::SyncSender<Result<(), CoreError>>),
    SignalShutdown(
        InstanceId,
        u32,
        mpsc::SyncSender<Result<Instant, CoreError>>,
    ),
    #[cfg(all(unix, test, feature = "test-support"))]
    FailNextJobCommit(mpsc::SyncSender<Result<(), CoreError>>),
    Close,
    #[cfg(test)]
    LimitDatabasePages(mpsc::SyncSender<Result<(), CoreError>>),
    #[cfg(test)]
    FailNextShutdownCommit,
    #[cfg(test)]
    PauseNextShutdown(mpsc::SyncSender<()>, Receiver<()>, mpsc::SyncSender<()>),
    #[cfg(test)]
    SeedOperationHistory(usize, mpsc::SyncSender<Result<(), CoreError>>),
}

/// Bounded handle to the only thread allowed to own SQLite and the lease.
/// Dropping the handle waits for the actor to close SQLite before releasing
/// authority, preventing another process from opening the store too early.
pub struct Store {
    sender: SyncSender<Command>,
    thread: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
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
            }),
            Err(error) => {
                let _ = thread.join();
                Err(error)
            }
        }
    }

    /// Read the durable installation and current instance identities.
    pub fn identity(&self) -> Result<StoreIdentity, CoreError> {
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        match self.sender.try_send(Command::Identity(response_tx)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(CoreError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(CoreError::StoreUnavailable);
            }
        }
        response_rx
            .recv()
            .map_err(|_| CoreError::StoreUnavailable)?
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
    ) -> Result<Option<dissect3d_api::AcceptanceReceipt>, crate::submission::SubmissionError> {
        self.request_job(|reply| Command::ProbeJobBinding(auth, key, request, reply))
    }

    #[cfg(unix)]
    pub(crate) fn accept_job(
        &self,
        auth: AuthContext,
        key: IdempotencyKey,
        request: dissect3d_api::JobRequest,
        candidate: crate::submission::admission::AdmissionCandidate,
    ) -> Result<dissect3d_api::AcceptanceReceipt, crate::submission::SubmissionError> {
        self.request_job(|reply| Command::AcceptJob(auth, key, request, Box::new(candidate), reply))
    }

    #[cfg(all(unix, test, feature = "test-support"))]
    pub(crate) fn set_test_job_limits(&self, limits: submission::AcceptanceLimits) {
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
        let (reply, receiver) = mpsc::sync_channel(1);
        assert!(
            self.sender
                .send(Command::AcceptJob(
                    auth,
                    key,
                    request,
                    Box::new(candidate),
                    reply
                ))
                .is_ok()
        );
        drop(receiver);
    }

    #[cfg(unix)]
    fn request_job<T>(
        &self,
        command: impl FnOnce(mpsc::SyncSender<Result<T, crate::submission::SubmissionError>>) -> Command,
    ) -> Result<T, crate::submission::SubmissionError> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.sender.try_send(command(tx)).map_err(|error| {
            crate::submission::SubmissionError::from(match error {
                mpsc::TrySendError::Full(_) => CoreError::Busy,
                mpsc::TrySendError::Disconnected(_) => CoreError::StoreUnavailable,
            })
        })?;
        rx.recv()
            .map_err(|_| crate::submission::SubmissionError::from(CoreError::StoreUnavailable))?
    }

    #[cfg(unix)]
    pub(crate) fn show_job(
        &self,
        auth: AuthContext,
        id: dissect3d_api::JobId,
    ) -> Result<dissect3d_api::JobSnapshot, crate::submission::SubmissionError> {
        self.request_job(|reply| Command::ShowJob(auth, id, reply))
    }
    #[cfg(unix)]
    pub(crate) fn list_jobs(
        &self,
        auth: AuthContext,
        query: dissect3d_api::JobsQuery,
    ) -> Result<dissect3d_api::JobPage, crate::submission::SubmissionError> {
        self.request_job(|reply| Command::ListJobs(auth, query, reply))
    }
    #[cfg(unix)]
    pub(crate) fn job_audit_batch(
        &self,
        after: String,
    ) -> Result<Vec<jobs::AuditEntry>, crate::submission::SubmissionError> {
        self.request_job(|reply| Command::JobAuditBatch(after, reply))
    }
    #[cfg(unix)]
    pub(crate) fn mark_job_input_fault(
        &self,
        id: InputId,
    ) -> Result<(), crate::submission::SubmissionError> {
        self.request_job(|reply| Command::MarkJobInputFault(id, reply))
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

    fn request<T>(
        &self,
        command: impl FnOnce(mpsc::SyncSender<Result<T, CoreError>>) -> Command,
    ) -> Result<T, CoreError> {
        // Capacity-one replies make each request self-contained while try_send
        // keeps queue saturation observable instead of blocking producers.
        let (response_tx, response_rx) = mpsc::sync_channel(1);
        match self.sender.try_send(command(response_tx)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => return Err(CoreError::Busy),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(CoreError::StoreUnavailable);
            }
        }
        response_rx
            .recv()
            .map_err(|_| CoreError::StoreUnavailable)?
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

fn actor(
    root: OwnedRoot,
    // Keep the lease in this stack frame until after the SQLite connection has
    // closed; declaration/drop order alone is not used as the lifetime proof.
    _lease: AuthorityLease,
    policy: CorePolicy,
    receiver: Receiver<Command>,
    ready: SyncSender<Result<(), CoreError>>,
    shutdown: Option<tokio::sync::mpsc::UnboundedSender<Instant>>,
    stopping_flag: Arc<AtomicBool>,
) {
    let mut connection = match open_database(&root, &policy) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    #[cfg(all(test, unix, feature = "test-support"))]
    let mut job_limits = submission::AcceptanceLimits::default();
    #[cfg(all(unix, not(all(test, feature = "test-support"))))]
    let job_limits = submission::AcceptanceLimits::default();
    let _ = ready.send(Ok(()));
    let mut stopping = false;
    let mut shutdown_deadline: Option<Instant> = None;
    #[cfg(unix)]
    let mut active_uploads = inputs::ActiveUploads::new();
    #[cfg(unix)]
    let mut input_pin_counts = inputs::InputPinCounts::new();
    #[cfg(unix)]
    let mut input_cleanup_cursor = inputs::CleanupCursor::default();
    #[cfg(test)]
    let mut fail_next_shutdown_commit = false;
    #[cfg(all(unix, test, feature = "test-support"))]
    let mut fail_next_job_commit = false;
    #[cfg(test)]
    let mut pause_next_shutdown: Option<(mpsc::SyncSender<()>, Receiver<()>)> = None;
    while let Ok(command) = receiver.recv() {
        match command {
            Command::Identity(response) => {
                let _ = response.send(read_identity(&connection));
            }
            Command::Enroll(enrollment, response) => {
                let result = if stopping {
                    Err(CoreError::Busy)
                } else {
                    enroll(&mut connection, enrollment)
                };
                let _ = response.send(result);
            }
            Command::Authenticate(client_id, digest, response) => {
                let _ = response.send(authenticate(&mut connection, client_id, digest));
            }
            Command::Snapshot(client_id, digest, response) => {
                let result = authenticate(&mut connection, client_id, digest).and_then(|context| {
                    let identity = read_identity(&connection)?;
                    Ok((identity, context))
                });
                let _ = response.send(result);
            }
            Command::Revoke(context, response) => {
                let result = if stopping {
                    Err(CoreError::Busy)
                } else {
                    revoke_self(&mut connection, context)
                };
                let _ = response.send(result);
            }
            Command::Shutdown(context, instance_id, key, response) => {
                #[cfg(test)]
                if let Some((started, release)) = pause_next_shutdown.take() {
                    let _ = started.send(());
                    let _ = release.recv();
                }
                #[cfg(test)]
                let fail_commit = std::mem::take(&mut fail_next_shutdown_commit);
                #[cfg(not(test))]
                let fail_commit = false;
                let attempt_started = Instant::now();
                let result = request_shutdown(
                    &mut connection,
                    context,
                    instance_id,
                    key,
                    stopping,
                    fail_commit,
                );
                if result.as_ref().is_ok_and(|receipt| {
                    matches!(
                        receipt.state,
                        OperationState::Queued | OperationState::Running
                    )
                }) {
                    stopping = true;
                    stopping_flag.store(true, Ordering::Release);
                    if let Ok(accepted) = &result {
                        let _ =
                            mark_shutdown_running(&mut connection, accepted.operation_id.as_str());
                    }
                    // This is emitted after request_shutdown commits. Replayed
                    // queued intent re-arms coordination if an earlier wakeup
                    // was delayed or consumed during coordinator startup.
                    if let Some(shutdown) = &shutdown {
                        let accepted = result.as_ref().expect("queued shutdown result");
                        let _ = mark_shutdown_quiescing(
                            &mut connection,
                            accepted.operation_id.as_str(),
                        );
                        if !accepted.replayed {
                            shutdown_deadline = Some(
                                attempt_started
                                    .checked_add(Duration::from_millis(
                                        policy.shutdown_timeout_ms.into(),
                                    ))
                                    .unwrap_or(attempt_started),
                            );
                        }
                        let deadline = shutdown_deadline.unwrap_or(attempt_started);
                        let _ = shutdown.send(deadline);
                    }
                }
                let _ = response.send(result);
            }
            Command::ShowOperation(context, operation_id, response) => {
                let _ = response.send(show_operation(&connection, context, operation_id));
            }
            #[cfg(unix)]
            Command::ReserveUpload(
                context,
                declared_length,
                media_type,
                available_space_bytes,
                response,
            ) => {
                let result = if stopping {
                    Err(CoreError::Busy)
                } else {
                    reserve_upload(
                        &mut connection,
                        context,
                        declared_length,
                        &media_type,
                        available_space_bytes,
                    )
                };
                let result = result.inspect(|reservation| {
                    active_uploads.insert(
                        reservation.reservation_id.clone(),
                        reservation.lease.clone(),
                    );
                });
                let _ = response.send(result);
            }
            #[cfg(unix)]
            Command::CompleteUpload(context, reservation, input, response) => {
                let reservation_id = reservation.reservation_id.clone();
                let result = if stopping {
                    Err(CoreError::Busy)
                } else {
                    complete_upload(&mut connection, context, reservation, input)
                };
                if result.is_ok() {
                    active_uploads.remove(&reservation_id);
                }
                let _ = response.send(result);
            }
            #[cfg(unix)]
            Command::AbandonUpload(reservation_id, response) => {
                let result = abandon_upload(&mut connection, &reservation_id);
                if result.is_ok() {
                    active_uploads.remove(&reservation_id);
                }
                let _ = response.send(result);
            }
            #[cfg(unix)]
            Command::PinVerifiedInputs(context, input_ids, response) => {
                let result =
                    inputs::pin_inputs(&mut connection, context, input_ids, &mut input_pin_counts);
                let _ = response.send(result);
            }
            #[cfg(unix)]
            Command::ClaimInputCleanup(requested_time_ms, response) => {
                let result = inputs::claim_input_cleanup(
                    &mut connection,
                    &mut active_uploads,
                    &mut input_pin_counts,
                    &mut input_cleanup_cursor,
                    requested_time_ms,
                );
                let _ = response.send(result);
            }
            #[cfg(unix)]
            Command::ConfirmInputCleanup(claim, response) => {
                let _ = response.send(inputs::confirm_input_cleanup(&mut connection, claim));
            }
            #[cfg(unix)]
            Command::InputFileKnown(input_id, response) => {
                let _ = response.send(inputs::input_file_known(&connection, &input_id));
            }
            #[cfg(unix)]
            Command::ProbeJobBinding(auth, key, request, reply) => {
                let _ = reply.send(submission::probe_committed(
                    &mut connection,
                    auth,
                    key,
                    request,
                ));
            }
            #[cfg(all(test, unix, feature = "test-support"))]
            Command::JobLimits(limits, reply) => {
                job_limits = limits;
                let _ = reply.send(Ok(()));
            }
            #[cfg(unix)]
            Command::AcceptJob(auth, key, request, candidate, reply) => {
                #[cfg(all(test, feature = "test-support"))]
                let fail_commit = std::mem::take(&mut fail_next_job_commit);
                #[cfg(not(all(test, feature = "test-support")))]
                let fail_commit = false;
                let _ = reply.send(submission::accept(
                    &mut connection,
                    &root,
                    auth,
                    key,
                    request,
                    *candidate,
                    submission::AcceptancePolicy {
                        stopping,
                        fail_commit,
                        response_limit: policy.control_response_bytes,
                        limits: job_limits,
                    },
                ));
            }
            #[cfg(unix)]
            Command::ShowJob(auth, id, reply) => {
                let _ = reply.send(jobs::show(
                    &connection,
                    auth,
                    id,
                    policy.control_response_bytes,
                ));
            }
            #[cfg(unix)]
            Command::ListJobs(auth, query, reply) => {
                let _ = reply.send(jobs::list(
                    &connection,
                    auth,
                    query,
                    policy.control_response_bytes,
                ));
            }
            #[cfg(all(unix, test, feature = "test-support"))]
            Command::FailNextJobCommit(reply) => {
                fail_next_job_commit = true;
                let _ = reply.send(Ok(()));
            }
            #[cfg(unix)]
            Command::JobAuditBatch(after, reply) => {
                let _ = reply.send(jobs::audit_batch(&connection, after));
            }
            #[cfg(unix)]
            Command::MarkJobInputFault(id, reply) => {
                let _ = reply.send(jobs::mark_fault(&connection, id));
            }
            Command::CompleteShutdown(instance_id, response) => {
                let _ = response.send(complete_shutdown(&mut connection, instance_id));
            }
            Command::SignalShutdown(instance_id, timeout_ms, response) => {
                let attempted = Instant::now();
                let deadline = attempted
                    .checked_add(Duration::from_millis(u64::from(timeout_ms)))
                    .unwrap_or(attempted);
                let result = if stopping {
                    shutdown_deadline.ok_or(CoreError::Busy)
                } else {
                    signal_shutdown(&mut connection, instance_id).map(|_| {
                        stopping = true;
                        stopping_flag.store(true, Ordering::Release);
                        shutdown_deadline = Some(deadline);
                        deadline
                    })
                };
                let _ = response.send(result);
            }
            #[cfg(test)]
            Command::LimitDatabasePages(response) => {
                let result = connection
                    .pragma_query_value(None, "page_count", |row| row.get::<_, u32>(0))
                    .map_err(|_| CoreError::StoreUnavailable)
                    .and_then(|pages| {
                        connection
                            .pragma_update(None, "max_page_count", pages.saturating_add(1))
                            .map_err(|_| CoreError::StoreUnavailable)
                    });
                let _ = response.send(result);
            }
            #[cfg(test)]
            Command::FailNextShutdownCommit => {
                fail_next_shutdown_commit = true;
            }
            #[cfg(test)]
            Command::PauseNextShutdown(started, release, configured) => {
                pause_next_shutdown = Some((started, release));
                let _ = configured.send(());
            }
            #[cfg(test)]
            Command::SeedOperationHistory(count, response) => {
                let result = (|| {
                    let transaction = connection
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .map_err(|_| CoreError::StoreUnavailable)?;
                    let identity = read_identity(&transaction)?;
                    let now = now_ms()?;
                    for index in 0..count {
                        let operation = format!("op_{index:032x}");
                        transaction
                            .execute(
                                "INSERT INTO core_operations(operation_id,client_id,idempotency_key,kind,instance_id,
                                 fingerprint,state,phase,created_at_ms,updated_at_ms)
                                 VALUES(?1,'cli_0123456789abcdef0123456789abcdef',?1,'engine.shutdown',?2,zeroblob(32),
                                 'succeeded','shutdown_committed',?3,?3)",
                                rusqlite::params![operation, identity.instance_id.as_str(), now],
                            )
                            .map_err(|_| CoreError::StoreUnavailable)?;
                    }
                    transaction
                        .commit()
                        .map_err(|_| CoreError::StoreUnavailable)
                })();
                let _ = response.send(result);
            }
            Command::Close => break,
        }
    }
    drop(connection);
    // The authority lease is dropped only after SQLite has closed.
}

fn open_database(root: &OwnedRoot, policy: &CorePolicy) -> Result<Connection, CoreError> {
    open_database_with_migrations(root, policy, &CORE_MIGRATIONS)
}

fn open_database_with_migrations(
    root: &OwnedRoot,
    policy: &CorePolicy,
    migrations: &[MigrationStep],
) -> Result<Connection, CoreError> {
    let database = RelativePath::parse(DATABASE_NAME).map_err(CoreError::Platform)?;
    let existing = match root.file_metadata(&database) {
        Ok(metadata) => Some(metadata.length),
        Err(PlatformError::NotFound) => None,
        Err(error) => return Err(CoreError::Platform(error)),
    };
    if existing.is_none() {
        root.write_atomic(&database, &[])
            .map_err(CoreError::Platform)?;
    }
    let path: PathBuf = root.path_for_native_vfs(&database);
    // The platform layer creates and validates this fixed file first. Keep
    // SQLite's standard VFS, disable URI interpretation, and ask SQLite to
    // reject a final-component symlink if the pathname changes before open.
    // This is defense in depth inside a protected per-user root, not a claim
    // that every SQLite operation is bound to the validated directory handle.
    let mut connection = open_internal_database(&path)?;
    connection
        .set_limit(
            limits::Limit::SQLITE_LIMIT_LENGTH,
            policy.maximum_value_bytes as i32,
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(
            policy.busy_timeout_ms.into(),
        ))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let app_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Inspect existing markers and journal mode before writable initialization
    // PRAGMAs. A future/foreign database must be rejected without mutating it.
    if existing.is_some_and(|length| length != 0) {
        if app_id != APPLICATION_ID || schema_version > SCHEMA_VERSION {
            return Err(CoreError::StoreIncompatible);
        }
        let current_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        if !current_mode.eq_ignore_ascii_case("wal") {
            return Err(CoreError::StoreIncompatible);
        }
    }
    configure_connection(&connection)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(CoreError::StoreIncompatible);
    }
    if existing.is_some_and(|length| length != 0) {
        run_migrations(&mut connection, root, migrations)?;
    }
    initialize_schema(&mut connection)?;
    verify_pragmas(&connection)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection) -> Result<(), CoreError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=256;
             PRAGMA journal_size_limit=4194304;",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    #[cfg(target_os = "macos")]
    connection
        .execute_batch("PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;")
        .map_err(|_| CoreError::StoreUnavailable)?;
    verify_pragmas(connection)
}

fn initialize_schema(connection: &mut Connection) -> Result<(), CoreError> {
    initialize_schema_with_hook(connection, || Ok(()))
}

fn initialize_schema_with_hook(
    connection: &mut Connection,
    before_commit: impl FnOnce() -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let app_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if app_id == APPLICATION_ID && version == SCHEMA_VERSION {
        // A new actor owns the exclusive lease, so prior active sessions cannot
        // still be serving requests. Record their loss and interrupt accepted
        // work in the same transaction that creates this session.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .execute(
                "UPDATE service_sessions SET termination='unclean', ended_at_ms=?1
                 WHERE termination='active'",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        before_commit()?;
        transaction
            .execute(
                "UPDATE core_operations SET state='interrupted', updated_at_ms=?1,
                 phase='interrupted' WHERE state IN ('queued','running')",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .execute(
                "UPDATE internal_shutdowns SET state='interrupted', phase='interrupted', updated_at_ms=?1
                 WHERE state IN ('queued','running')",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        let instance = new_instance_id()?;
        transaction
            .execute(
                "INSERT INTO service_sessions(instance_id,started_at_ms,ended_at_ms,termination)
                 VALUES(?1,?2,NULL,'active')",
                rusqlite::params![instance.as_str(), now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| CoreError::StoreUnavailable)?;
        return Ok(());
    }
    if app_id != 0 || version != 0 {
        return Err(CoreError::StoreIncompatible);
    }
    let installation = new_installation_id()?;
    let instance = new_instance_id()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Schema and its SQLite ownership/version markers commit together; a crash
    // cannot advertise a version whose tables were only partly created.
    transaction
        .execute_batch(
            "CREATE TABLE engine_identity (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                installation_id TEXT UNIQUE NOT NULL,
                created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE service_sessions (
                instance_id TEXT PRIMARY KEY,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                termination TEXT NOT NULL CHECK(termination IN ('active','clean','unclean'))
             );
             CREATE TABLE credentials (
                client_id TEXT PRIMARY KEY,
                enrollment_id TEXT UNIQUE NOT NULL,
                secret_digest BLOB NOT NULL CHECK(length(secret_digest)=32),
                client_kind TEXT NOT NULL CHECK(client_kind='cli'),
                grant_policy TEXT NOT NULL DEFAULT 'core-v1'
                    CHECK(grant_policy IN ('core-v1','submission-v1')),
                created_at_ms INTEGER NOT NULL,
                revoked_at_ms INTEGER
             );
             CREATE TABLE credential_grants (
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                operation TEXT NOT NULL,
                PRIMARY KEY(client_id,operation)
             );
             CREATE TABLE core_operations (
                operation_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                idempotency_key TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind='engine.shutdown'),
                instance_id TEXT NOT NULL REFERENCES service_sessions(instance_id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                error_code TEXT,
                UNIQUE(client_id,kind,idempotency_key)
             );
             CREATE TABLE internal_shutdowns (
                operation_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL UNIQUE REFERENCES service_sessions(instance_id),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE input_upload_reservations (
                reservation_id TEXT PRIMARY KEY,
                input_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                declared_length INTEGER NOT NULL CHECK(declared_length BETWEEN 1 AND 268435456),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                created_at_ms INTEGER NOT NULL
             );
             CREATE INDEX input_upload_reservations_owner
                ON input_upload_reservations(client_id,created_at_ms);
             CREATE TABLE captured_inputs (
                input_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 268435456),
                sha256 BLOB NOT NULL CHECK(length(sha256)=32),
                completed_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>completed_at_ms),
                cleanup_state TEXT NOT NULL DEFAULT 'complete'
                    CHECK(cleanup_state IN ('complete','deleting'))
             );
             CREATE INDEX captured_inputs_owner_expiry
                ON captured_inputs(client_id,expires_at_ms);
             CREATE TABLE engine_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>=0)
             );
             ",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    add_job_tables(&transaction)?;
    transaction
        .execute(
            "INSERT INTO engine_clock(singleton,last_observed_ms) VALUES(1,?1)",
            [now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT INTO engine_identity(singleton,installation_id,created_at_ms)
             VALUES(1,?1,?2)",
            rusqlite::params![installation.as_str(), now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT INTO service_sessions(instance_id,started_at_ms,termination)
             VALUES(?1,?2,'active')",
            rusqlite::params![instance.as_str(), now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| CoreError::StoreUnavailable)?;
    before_commit()?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

fn verify_pragmas(connection: &Connection) -> Result<(), CoreError> {
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let wal_autocheckpoint: i64 = connection
        .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let journal_size_limit: i64 = connection
        .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    #[cfg(target_os = "macos")]
    let mac_fullsync = {
        let fullfsync: i64 = connection
            .query_row("PRAGMA fullfsync", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        let checkpoint_fullfsync: i64 = connection
            .query_row("PRAGMA checkpoint_fullfsync", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        fullfsync == 1 && checkpoint_fullfsync == 1
    };
    #[cfg(not(target_os = "macos"))]
    let mac_fullsync = true;
    if foreign_keys == 1
        && trusted_schema == 0
        && synchronous == 2
        && wal_autocheckpoint == 256
        && journal_size_limit == 4_194_304
        && mac_fullsync
    {
        Ok(())
    } else {
        Err(CoreError::StoreIncompatible)
    }
}

struct MigrationStep {
    from: i64,
    to: i64,
    apply: fn(&Transaction<'_>) -> Result<(), CoreError>,
}

const CORE_MIGRATIONS: [MigrationStep; 5] = [
    MigrationStep {
        from: 1,
        to: 2,
        apply: add_internal_shutdown_table,
    },
    MigrationStep {
        from: 2,
        to: 3,
        apply: add_credential_grant_policy,
    },
    MigrationStep {
        from: 3,
        to: 4,
        apply: add_input_capture_tables,
    },
    MigrationStep {
        from: 4,
        to: 5,
        apply: add_input_cleanup_state,
    },
    MigrationStep {
        from: 5,
        to: 6,
        apply: add_job_tables,
    },
];

fn add_internal_shutdown_table(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "CREATE TABLE internal_shutdowns (
                operation_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL UNIQUE REFERENCES service_sessions(instance_id),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

fn add_job_tables(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction.execute_batch(
        "CREATE TABLE jobs (
            job_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            acceptance_sequence INTEGER NOT NULL UNIQUE CHECK(acceptance_sequence>0),
            created_at_ms INTEGER NOT NULL,
            resolved_json TEXT NOT NULL,
            storage_status TEXT NOT NULL CHECK(storage_status IN ('verified','storage_integrity_fault'))
         );
         CREATE INDEX jobs_creator_sequence ON jobs(client_id,acceptance_sequence);
         CREATE TABLE submission_bindings (
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            operation TEXT NOT NULL CHECK(operation='jobs.submit'),
            idempotency_key TEXT NOT NULL,
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            canonicalization_version INTEGER NOT NULL CHECK(canonicalization_version=1),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            original_inputs_json TEXT NOT NULL,
            PRIMARY KEY(client_id,operation,idempotency_key)
         );
         CREATE TABLE job_inputs (
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            input_id TEXT NOT NULL REFERENCES captured_inputs(input_id),
            PRIMARY KEY(job_id,input_id)
         );
         CREATE INDEX job_inputs_by_input ON job_inputs(input_id);
         CREATE TABLE job_acceptance_events (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
            acceptance_sequence INTEGER NOT NULL UNIQUE,
            snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision=1)
         );
         CREATE TABLE job_sequence (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            value INTEGER NOT NULL CHECK(value>=0)
         );
         INSERT INTO job_sequence(singleton,value) VALUES(1,0);"
    ).map_err(|_| CoreError::StoreUnavailable)
}

fn add_credential_grant_policy(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE credentials ADD COLUMN grant_policy TEXT NOT NULL DEFAULT 'core-v1'
             CHECK(grant_policy IN ('core-v1','submission-v1'));",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

fn add_input_capture_tables(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "CREATE TABLE input_upload_reservations (
                reservation_id TEXT PRIMARY KEY,
                input_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                declared_length INTEGER NOT NULL CHECK(declared_length BETWEEN 1 AND 268435456),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                created_at_ms INTEGER NOT NULL
             );
             CREATE INDEX input_upload_reservations_owner
                ON input_upload_reservations(client_id,created_at_ms);
             CREATE TABLE captured_inputs (
                input_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 268435456),
                sha256 BLOB NOT NULL CHECK(length(sha256)=32),
                completed_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>completed_at_ms)
             );
             CREATE INDEX captured_inputs_owner_expiry
                ON captured_inputs(client_id,expires_at_ms);",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

fn add_input_cleanup_state(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE captured_inputs ADD COLUMN cleanup_state TEXT NOT NULL DEFAULT 'complete'
                CHECK(cleanup_state IN ('complete','deleting'));
             CREATE TABLE IF NOT EXISTS engine_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>=0)
             );",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let now = now_ms()?;
    let last_completion: i64 = transaction
        .query_row(
            "SELECT coalesce(max(completed_at_ms),0) FROM captured_inputs",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO engine_clock(singleton,last_observed_ms) VALUES(1,?1)",
            [now.max(last_completion)],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

/// Apply only a private, contiguous migration registry after retaining a
/// verified online backup. Every step runs with verified durability settings.
fn run_migrations(
    connection: &mut Connection,
    root: &OwnedRoot,
    migrations: &[MigrationStep],
) -> Result<(), CoreError> {
    run_migrations_with_backup_at(connection, root, migrations, retain_verified_backup_at)
}

fn run_migrations_with_backup_at(
    connection: &mut Connection,
    root: &OwnedRoot,
    migrations: &[MigrationStep],
    retain_backup: impl FnOnce(&Connection, &OwnedRoot, &RelativePath) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let mut version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let mut pending = Vec::new();
    let mut next_version = version;
    // Build and validate the complete contiguous chain before taking a backup
    // or running any migration, so a gap cannot leave a partially upgraded DB.
    while let Some(step) = migrations.iter().find(|step| step.from == next_version) {
        if step.to != next_version + 1 {
            return Err(CoreError::StoreIncompatible);
        }
        pending.push(step);
        next_version = step.to;
    }
    if pending.is_empty() {
        return if version == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(CoreError::StoreIncompatible)
        };
    }
    // Retain a verified pre-upgrade copy before the single transaction changes
    // schema and user_version together.
    let backup_path = recovery_backup_for_version(next_version)?;
    retain_backup(connection, root, &backup_path)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    for step in pending {
        if step.from != version || step.to != version + 1 {
            return Err(CoreError::StoreIncompatible);
        }
        (step.apply)(&transaction)?;
        transaction
            .pragma_update(None, "user_version", step.to)
            .map_err(|_| CoreError::StoreUnavailable)?;
        version = step.to;
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

fn recovery_backup_for_version(version: i64) -> Result<RelativePath, CoreError> {
    let path = match version {
        3 => RECOVERY_BACKUP.to_owned(),
        4 => RECOVERY_BACKUP_V4.to_owned(),
        5 => RECOVERY_BACKUP_V5.to_owned(),
        _ => format!("recovery/metadata-v{version}-upgrade.sqlite3"),
    };
    RelativePath::parse(path).map_err(CoreError::Platform)
}

fn retain_verified_backup_at(
    connection: &Connection,
    root: &OwnedRoot,
    backup_relative: &RelativePath,
) -> Result<(), CoreError> {
    retain_verified_backup_at_with_sync(connection, root, backup_relative, |backup_path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(backup_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| CoreError::StoreUnavailable)
    })
}

fn retain_verified_backup_at_with_sync(
    connection: &Connection,
    root: &OwnedRoot,
    backup_relative: &RelativePath,
    sync_backup: impl FnOnce(&Path) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let existing = root.file_metadata(backup_relative);
    match existing {
        Ok(_) => return Err(CoreError::StoreIncompatible),
        Err(PlatformError::NotFound) => {}
        Err(error) => return Err(CoreError::Platform(error)),
    }
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Refuse an unexpectedly large source rather than consuming unbounded disk
    // during recovery. An existing backup is preserved, never overwritten.
    if page_count < 0
        || page_size < 0
        || page_count.saturating_mul(page_size) > RECOVERY_BACKUP_LIMIT_BYTES
    {
        return Err(CoreError::StoreIncompatible);
    }
    let backup_bytes = page_count.saturating_mul(page_size) as u64;
    let available_bytes = root.available_space_bytes().map_err(CoreError::Platform)?;
    require_recovery_backup_space(available_bytes, backup_bytes)?;
    root.write_atomic(backup_relative, &[])
        .map_err(CoreError::Platform)?;
    let backup_path = root.path_for_native_vfs(backup_relative);
    // The fixed backup file was created through OwnedRoot above; do not let
    // SQLite choose a different URI target or create a missing path itself.
    let mut backup_connection = open_internal_database(&backup_path)?;
    configure_connection(&backup_connection)?;
    let backup = rusqlite::backup::Backup::new(connection, &mut backup_connection)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // SQLite backup can report transient contention between pages; retry only
    // within a fixed budget so startup cannot wait forever on another writer.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match backup.step(64).map_err(|_| CoreError::StoreUnavailable)? {
            rusqlite::backup::StepResult::Done => break,
            rusqlite::backup::StepResult::More => {}
            rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked => {
                if std::time::Instant::now() >= deadline {
                    return Err(CoreError::Busy);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => return Err(CoreError::StoreUnavailable),
        }
    }
    drop(backup);
    let integrity: String = backup_connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if integrity != "ok" {
        return Err(CoreError::InvalidStore);
    }
    backup_connection
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|_| CoreError::StoreUnavailable)?;
    backup_connection
        .close()
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Windows FlushFileBuffers requires a writable handle; never truncate it.
    sync_backup(&backup_path)?;
    Ok(())
}

fn require_recovery_backup_space(available_bytes: u64, backup_bytes: u64) -> Result<(), CoreError> {
    let required = backup_bytes.saturating_add(RECOVERY_BACKUP_FREE_SPACE_FLOOR_BYTES);
    if available_bytes < required {
        Err(CoreError::StoreUnavailable)
    } else {
        Ok(())
    }
}

fn read_identity(connection: &Connection) -> Result<StoreIdentity, CoreError> {
    let installation: String = connection
        .query_row(
            "SELECT installation_id FROM engine_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?
        .ok_or(CoreError::InvalidStore)?;
    let instance: String = connection
        .query_row(
            "SELECT instance_id FROM service_sessions WHERE termination='active' ORDER BY started_at_ms DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?
        .ok_or(CoreError::InvalidStore)?;
    Ok(StoreIdentity {
        installation_id: InstallationId::parse(installation)
            .map_err(|_| CoreError::InvalidStore)?,
        instance_id: InstanceId::parse(instance).map_err(|_| CoreError::InvalidStore)?,
    })
}

fn enroll(
    connection: &mut Connection,
    enrollment: VerifiedEnrollment,
) -> Result<EnrollmentReceipt, CoreError> {
    // Recheck the native owner at the persistence boundary rather than relying
    // solely on the transport's earlier peer-credential observation.
    let actual_owner = current_owner_identity().map_err(CoreError::Platform)?;
    if actual_owner != enrollment.owner {
        return Err(CoreError::Unauthorized);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let identity = read_identity(&transaction)?;
    if identity.installation_id != enrollment.installation_id
        || identity.instance_id != enrollment.instance_id
    {
        return Err(CoreError::Conflict);
    }
    let existing: Option<ExistingCredential> = transaction
        .query_row(
            "SELECT client_id,enrollment_id,secret_digest,grant_policy,created_at_ms,revoked_at_ms
             FROM credentials WHERE enrollment_id=?1 OR client_id=?2 LIMIT 1",
            rusqlite::params![
                enrollment.enrollment_id.as_str(),
                enrollment.client_id.as_str()
            ],
            |row| {
                Ok(ExistingCredential {
                    client_id: row.get(0)?,
                    enrollment_id: row.get(1)?,
                    digest: row.get(2)?,
                    grant_policy: row.get(3)?,
                    created_at_ms: row.get(4)?,
                    revoked_at_ms: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if let Some(existing) = existing {
        // Idempotency is exact: identity and digest must both match, and a
        // revoked enrollment cannot be revived by replaying its old request.
        use subtle::ConstantTimeEq as _;
        let exact_identity = existing.client_id == enrollment.client_id.as_str()
            && existing.enrollment_id == enrollment.enrollment_id.as_str();
        let existing_policy =
            GrantPolicy::parse(&existing.grant_policy).ok_or(CoreError::InvalidStore)?;
        let exact_digest = existing.digest.len() == 32
            && existing
                .digest
                .as_slice()
                .ct_eq(enrollment.token_digest.as_bytes().as_slice())
                .unwrap_u8()
                == 1;
        if !exact_identity || !exact_digest || existing_policy != enrollment.grant_policy {
            return Err(CoreError::Conflict);
        }
        if existing.revoked_at_ms.is_some() {
            return Err(CoreError::Unauthorized);
        }
        let grants = read_validated_grants(&transaction, &enrollment.client_id)?;
        let receipt = enrollment_receipt(
            enrollment.installation_id,
            enrollment.client_id,
            enrollment.enrollment_id,
            grants,
            existing.created_at_ms,
            true,
        )?;
        transaction
            .commit()
            .map_err(|_| CoreError::StoreUnavailable)?;
        return Ok(receipt);
    }
    let credential_count: i64 = transaction
        .query_row("SELECT count(*) FROM credentials", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if credential_count >= MAX_CREDENTIAL_ROWS {
        return Err(CoreError::LimitReached);
    }
    let created_at_ms = now_ms()?;
    transaction
        .execute(
            "INSERT INTO credentials(client_id,enrollment_id,secret_digest,client_kind,grant_policy,created_at_ms)
             VALUES(?1,?2,?3,'cli',?4,?5)",
            rusqlite::params![
                enrollment.client_id.as_str(),
                enrollment.enrollment_id.as_str(),
                enrollment.token_digest.as_bytes().as_slice(),
                enrollment.grant_policy.as_str(),
                created_at_ms
            ],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    for grant in enrollment.grant_policy.grants() {
        transaction
            .execute(
                "INSERT INTO credential_grants(client_id,operation) VALUES(?1,?2)",
                rusqlite::params![enrollment.client_id.as_str(), grant],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
    }
    let receipt = enrollment_receipt(
        enrollment.installation_id,
        enrollment.client_id,
        enrollment.enrollment_id,
        enrollment
            .grant_policy
            .grants()
            .iter()
            .map(|grant| (*grant).to_owned())
            .collect(),
        created_at_ms,
        false,
    )?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(receipt)
}

fn authenticate(
    connection: &mut Connection,
    client_id: ClientId,
    token_digest: TokenDigest,
) -> Result<AuthContext, CoreError> {
    use subtle::ConstantTimeEq as _;
    // Use a transaction for identity, credential, and grants so the returned
    // authorization context reflects one consistent database snapshot.
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let identity = read_identity(&transaction)?;
    let credential: Option<(Vec<u8>, Option<i64>, String)> = transaction
        .query_row(
            "SELECT secret_digest,revoked_at_ms,grant_policy FROM credentials WHERE client_id=?1",
            [client_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let Some((stored_digest, revoked_at_ms, grant_policy)) = credential else {
        return Err(CoreError::Unauthorized);
    };
    let grant_policy = GrantPolicy::parse(&grant_policy).ok_or(CoreError::InvalidStore)?;
    if revoked_at_ms.is_some()
        || stored_digest.len() != 32
        || stored_digest
            .as_slice()
            .ct_eq(token_digest.as_bytes().as_slice())
            .unwrap_u8()
            != 1
    {
        return Err(CoreError::Unauthorized);
    }
    let grants = read_grants(&transaction, &client_id)?;
    validate_grants_for_policy(grant_policy, &grants)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(AuthContext {
        installation_id: identity.installation_id,
        client_id,
        granted_operations: grants,
    })
}

#[cfg(unix)]
fn require_active_grant(
    connection: &Connection,
    context: &AuthContext,
    required: &str,
) -> Result<(), CoreError> {
    let identity = read_identity(connection)?;
    if identity.installation_id != context.installation_id {
        return Err(CoreError::Unauthorized);
    }
    let revoked_at: Option<Option<i64>> = connection
        .query_row(
            "SELECT revoked_at_ms FROM credentials WHERE client_id=?1",
            [context.client_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !matches!(revoked_at, Some(None)) {
        return Err(CoreError::Unauthorized);
    }
    let grants = read_validated_grants(connection, &context.client_id)?;
    if !grants.iter().any(|grant| grant == required) {
        return Err(CoreError::Unauthorized);
    }
    Ok(())
}

fn revoke_self(
    connection: &mut Connection,
    context: AuthContext,
) -> Result<RevocationReceipt, CoreError> {
    // The context is bound to this installation and client. Re-read current
    // grants inside the write transaction so stale contexts cannot restore or
    // broaden authority after a policy change or prior revocation.
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let identity = read_identity(&transaction)?;
    if identity.installation_id != context.installation_id {
        return Err(CoreError::Unauthorized);
    }
    let revoked_at_ms = now_ms()?;
    let revoked: Option<Option<i64>> = transaction
        .query_row(
            "SELECT revoked_at_ms FROM credentials WHERE client_id=?1",
            [context.client_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if revoked.flatten().is_some() {
        return Err(CoreError::Unauthorized);
    }
    if revoked.is_none() {
        return Err(CoreError::Unauthorized);
    }
    let grants = read_validated_grants(&transaction, &context.client_id)?;
    if !grants.iter().any(|grant| grant == "auth.revoke_self") {
        return Err(CoreError::Unauthorized);
    }
    transaction
        .execute(
            "UPDATE credentials SET revoked_at_ms=?2 WHERE client_id=?1 AND revoked_at_ms IS NULL",
            rusqlite::params![context.client_id.as_str(), revoked_at_ms],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(RevocationReceipt {
        api_version: "1.0".to_owned(),
        client_id: context.client_id,
        revoked: true,
        revoked_at_ms: TimestampMs::new(revoked_at_ms as u64)
            .map_err(|_| CoreError::StoreUnavailable)?,
    })
}

fn request_shutdown(
    connection: &mut Connection,
    context: AuthContext,
    requested_instance: InstanceId,
    key: IdempotencyKey,
    stopping: bool,
    fail_before_commit: bool,
) -> Result<ShutdownAcceptance, CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let installation: String = transaction
        .query_row(
            "SELECT installation_id FROM engine_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if InstallationId::parse(installation).map_err(|_| CoreError::InvalidStore)?
        != context.installation_id
    {
        return Err(CoreError::Unauthorized);
    }
    let grants = read_validated_grants(&transaction, &context.client_id)?;
    if !grants.iter().any(|grant| grant == "engine.shutdown") {
        return Err(CoreError::Unauthorized);
    }
    let active: Option<Option<i64>> = transaction
        .query_row(
            "SELECT revoked_at_ms FROM credentials WHERE client_id=?1",
            [context.client_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !matches!(active, Some(None)) {
        return Err(CoreError::Unauthorized);
    }
    let fingerprint = shutdown_fingerprint(&requested_instance);
    let existing: Option<(String, String, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT operation_id,instance_id,fingerprint,created_at_ms FROM core_operations
             WHERE client_id=?1 AND kind='engine.shutdown' AND idempotency_key=?2",
            rusqlite::params![context.client_id.as_str(), key.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if let Some((operation, instance, stored_fingerprint, created_at_ms)) = existing {
        use subtle::ConstantTimeEq as _;
        if instance != requested_instance.as_str()
            || stored_fingerprint.len() != fingerprint.len()
            || stored_fingerprint
                .as_slice()
                .ct_eq(fingerprint.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(CoreError::Conflict);
        }
        let state: String = transaction
            .query_row(
                "SELECT state FROM core_operations WHERE operation_id=?1",
                [&operation],
                |row| row.get(0),
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        let receipt = shutdown_receipt(
            operation,
            requested_instance,
            state_from_db(&state)?,
            created_at_ms,
            true,
        )?;
        transaction
            .commit()
            .map_err(|_| CoreError::StoreUnavailable)?;
        return Ok(receipt);
    }
    let identity = read_identity(&transaction)?;
    if identity.instance_id != requested_instance {
        return Err(CoreError::Conflict);
    }
    let active_count: i64 = transaction
        .query_row(
            "SELECT count(*) FROM core_operations WHERE kind='engine.shutdown' AND state IN ('queued','running')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if active_count >= 16 {
        return Err(CoreError::LimitReached);
    }
    // Replays were resolved above; a full history must reject only new rows.
    let total_operations: i64 = transaction
        .query_row("SELECT count(*) FROM core_operations", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if total_operations >= MAX_CORE_OPERATION_ROWS {
        return Err(CoreError::LimitReached);
    }
    if stopping {
        return Err(CoreError::Busy);
    }
    let operation_id =
        OperationId::parse(random_id("op_")?).map_err(|_| CoreError::StoreUnavailable)?;
    let accepted_at_ms = now_ms()?;
    transaction
        .execute(
            "INSERT INTO core_operations(operation_id,client_id,idempotency_key,kind,instance_id,
             fingerprint,state,phase,created_at_ms,updated_at_ms)
             VALUES(?1,?2,?3,'engine.shutdown',?4,?5,'queued','accepted',?6,?6)",
            rusqlite::params![
                operation_id.as_str(),
                context.client_id.as_str(),
                key.as_str(),
                requested_instance.as_str(),
                fingerprint.as_slice(),
                accepted_at_ms,
            ],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if fail_before_commit {
        return Err(CoreError::StoreUnavailable);
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    shutdown_receipt(
        operation_id.as_str().to_owned(),
        requested_instance,
        OperationState::Queued,
        accepted_at_ms,
        false,
    )
}

fn shutdown_fingerprint(instance_id: &InstanceId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"core-shutdown-v1\n");
    hasher.update(instance_id.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.finalize().into()
}

fn signal_shutdown(
    connection: &mut Connection,
    instance_id: InstanceId,
) -> Result<OperationId, CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let active: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM service_sessions WHERE instance_id=?1 AND termination='active')",
            [instance_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !active {
        return Err(CoreError::Conflict);
    }
    let operation_id =
        OperationId::parse(random_id("op_")?).map_err(|_| CoreError::StoreUnavailable)?;
    let timestamp = now_ms()?;
    transaction
        .execute(
            "INSERT INTO internal_shutdowns(operation_id,instance_id,state,phase,created_at_ms,updated_at_ms)
             VALUES(?1,?2,'running','quiescing',?3,?3)",
            rusqlite::params![operation_id.as_str(), instance_id.as_str(), timestamp],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(operation_id)
}

fn mark_shutdown_running(connection: &mut Connection, operation_id: &str) -> Result<(), CoreError> {
    connection
        .execute(
            "UPDATE core_operations SET state='running',phase='running',updated_at_ms=?2
             WHERE operation_id=?1 AND state='queued' AND phase='accepted'",
            rusqlite::params![operation_id, now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

fn mark_shutdown_quiescing(
    connection: &mut Connection,
    operation_id: &str,
) -> Result<(), CoreError> {
    connection
        .execute(
            "UPDATE core_operations SET state='running',phase='quiescing',updated_at_ms=?2
             WHERE operation_id=?1 AND state='running' AND phase='running'",
            rusqlite::params![operation_id, now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

fn show_operation(
    connection: &Connection,
    context: AuthContext,
    operation_id: OperationId,
) -> Result<OperationSnapshot, CoreError> {
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let installation: String = transaction
        .query_row(
            "SELECT installation_id FROM engine_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if InstallationId::parse(installation).map_err(|_| CoreError::InvalidStore)?
        != context.installation_id
    {
        return Err(CoreError::Unauthorized);
    }
    let grants = read_validated_grants(&transaction, &context.client_id)?;
    if !grants.iter().any(|grant| grant == "operation.show_own") {
        return Err(CoreError::Unauthorized);
    }
    let active: Option<Option<i64>> = transaction
        .query_row(
            "SELECT revoked_at_ms FROM credentials WHERE client_id=?1",
            [context.client_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !matches!(active, Some(None)) {
        return Err(CoreError::Unauthorized);
    }
    let record: Option<OperationRecord> = transaction
        .query_row(
            "SELECT operation_id,kind,instance_id,state,phase,created_at_ms,updated_at_ms,error_code
             FROM core_operations WHERE operation_id=?1 AND client_id=?2",
            rusqlite::params![operation_id.as_str(), context.client_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let Some((operation, kind, instance, state, phase, created, updated, error)) = record else {
        return Err(CoreError::NotFound);
    };
    if kind != "engine.shutdown"
        || !matches!(
            phase.as_str(),
            "accepted" | "running" | "quiescing" | "shutdown_committed" | "interrupted"
        )
        || error.as_ref().is_some_and(|value| {
            value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        })
    {
        return Err(CoreError::InvalidStore);
    }
    let snapshot = OperationSnapshot {
        api_version: "1.0".to_owned(),
        operation_id: OperationId::parse(operation).map_err(|_| CoreError::InvalidStore)?,
        kind,
        target: OperationTarget {
            kind: "engine".to_owned(),
            instance_id: InstanceId::parse(instance).map_err(|_| CoreError::InvalidStore)?,
        },
        state: state_from_db(&state)?,
        phase,
        created_at_ms: TimestampMs::new(
            u64::try_from(created).map_err(|_| CoreError::InvalidStore)?,
        )
        .map_err(|_| CoreError::InvalidStore)?,
        updated_at_ms: TimestampMs::new(
            u64::try_from(updated).map_err(|_| CoreError::InvalidStore)?,
        )
        .map_err(|_| CoreError::InvalidStore)?,
        error,
    };
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(snapshot)
}

fn complete_shutdown(
    connection: &mut Connection,
    instance_id: InstanceId,
) -> Result<(), CoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let ended_at_ms = now_ms()?;
    let changed = transaction
        .execute(
            "UPDATE service_sessions SET termination='clean',ended_at_ms=?2
             WHERE instance_id=?1 AND termination='active'",
            rusqlite::params![instance_id.as_str(), ended_at_ms],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if changed != 1 {
        return Err(CoreError::Conflict);
    }
    transaction
        .execute(
            "UPDATE core_operations SET state='succeeded',phase='shutdown_committed',updated_at_ms=?2
             WHERE kind='engine.shutdown' AND instance_id=?1 AND state IN ('queued','running')",
            rusqlite::params![instance_id.as_str(), ended_at_ms],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "UPDATE internal_shutdowns SET state='succeeded',phase='shutdown_committed',updated_at_ms=?2
             WHERE instance_id=?1 AND state IN ('queued','running')",
            rusqlite::params![instance_id.as_str(), ended_at_ms],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)
}

fn state_from_db(value: &str) -> Result<OperationState, CoreError> {
    match value {
        "queued" => Ok(OperationState::Queued),
        "running" => Ok(OperationState::Running),
        "succeeded" => Ok(OperationState::Succeeded),
        "failed" => Ok(OperationState::Failed),
        "interrupted" => Ok(OperationState::Interrupted),
        _ => Err(CoreError::InvalidStore),
    }
}

fn shutdown_receipt(
    operation: String,
    instance_id: InstanceId,
    state: OperationState,
    accepted_at_ms: i64,
    replayed: bool,
) -> Result<ShutdownAcceptance, CoreError> {
    Ok(ShutdownAcceptance {
        api_version: "1.0".to_owned(),
        operation_id: OperationId::parse(operation).map_err(|_| CoreError::InvalidStore)?,
        instance_id,
        state,
        accepted_at_ms: TimestampMs::new(
            u64::try_from(accepted_at_ms).map_err(|_| CoreError::InvalidStore)?,
        )
        .map_err(|_| CoreError::InvalidStore)?,
        replayed,
    })
}

fn read_grants(connection: &Connection, client_id: &ClientId) -> Result<Vec<String>, CoreError> {
    let mut statement = connection
        .prepare("SELECT operation FROM credential_grants WHERE client_id=?1 ORDER BY operation")
        .map_err(|_| CoreError::StoreUnavailable)?;
    let grants = statement
        .query_map([client_id.as_str()], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?
        .collect::<Result<Vec<String>, _>>()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(grants)
}

fn read_validated_grants(
    connection: &Connection,
    client_id: &ClientId,
) -> Result<Vec<String>, CoreError> {
    let policy: String = connection
        .query_row(
            "SELECT grant_policy FROM credentials WHERE client_id=?1",
            [client_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?
        .ok_or(CoreError::InvalidStore)?;
    let policy = GrantPolicy::parse(&policy).ok_or(CoreError::InvalidStore)?;
    let grants = read_grants(connection, client_id)?;
    validate_grants_for_policy(policy, &grants)?;
    Ok(grants)
}

fn validate_grants_for_policy(policy: GrantPolicy, grants: &[String]) -> Result<(), CoreError> {
    let mut expected = policy
        .grants()
        .iter()
        .map(|grant| (*grant).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    if grants == expected {
        Ok(())
    } else {
        Err(CoreError::InvalidStore)
    }
}

fn enrollment_receipt(
    installation_id: InstallationId,
    client_id: ClientId,
    enrollment_id: dissect3d_api::EnrollmentId,
    granted_operations: Vec<String>,
    created_at_ms: i64,
    replayed: bool,
) -> Result<EnrollmentReceipt, CoreError> {
    let created_at_ms = u64::try_from(created_at_ms).map_err(|_| CoreError::InvalidStore)?;
    Ok(EnrollmentReceipt {
        bootstrap_version: "1.0".to_owned(),
        installation_id,
        client_id,
        enrollment_id,
        granted_operations,
        created_at_ms: TimestampMs::new(created_at_ms).map_err(|_| CoreError::InvalidStore)?,
        replayed,
    })
}

fn new_installation_id() -> Result<InstallationId, CoreError> {
    InstallationId::parse(random_id("ins_")?).map_err(|_| CoreError::StoreUnavailable)
}

fn new_instance_id() -> Result<InstanceId, CoreError> {
    InstanceId::parse(random_id("eng_")?).map_err(|_| CoreError::StoreUnavailable)
}

pub(crate) fn random_id(prefix: &str) -> Result<String, CoreError> {
    let mut entropy = [0_u8; 16];
    getrandom::fill(&mut entropy).map_err(|_| CoreError::StoreUnavailable)?;
    let mut value = String::with_capacity(prefix.len() + 32);
    value.push_str(prefix);
    for byte in entropy {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").map_err(|_| CoreError::StoreUnavailable)?;
    }
    Ok(value)
}

#[cfg(unix)]
fn digest_hex(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn now_ms() -> Result<i64, CoreError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CoreError::StoreUnavailable)?;
    i64::try_from(elapsed.as_millis()).map_err(|_| CoreError::StoreUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_platform::{AuthorityLease, RootPurpose};
    use std::time::Duration;

    fn injected_migration_failure(_: &Transaction<'_>) -> Result<(), CoreError> {
        Err(CoreError::StoreUnavailable)
    }

    fn add_temporary_migration_table(transaction: &Transaction<'_>) -> Result<(), CoreError> {
        transaction
            .execute_batch("CREATE TABLE temporary_migration_probe(value INTEGER);")
            .map_err(|_| CoreError::StoreUnavailable)
    }

    #[cfg(unix)]
    #[test]
    fn migrations_execute_under_required_connection_safety_policy() {
        fn checked_migration(transaction: &Transaction<'_>) -> Result<(), CoreError> {
            verify_pragmas(transaction)?;
            add_internal_shutdown_table(transaction)
        }
        let temp = tempfile::tempdir().unwrap();
        let root = OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData)
            .unwrap();
        let lease = AuthorityLease::acquire(&root).unwrap();
        let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
        drop(store);
        let root = OwnedRoot::open(&temp.path().join("engine"), RootPurpose::EngineData).unwrap();
        let path = root.path_for_native_vfs(&RelativePath::parse(DATABASE_NAME).unwrap());
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch("DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs; DROP TABLE input_upload_reservations; DROP TABLE internal_shutdowns; ALTER TABLE credentials DROP COLUMN grant_policy; PRAGMA user_version=1;")
            .unwrap();
        drop(connection);
        let _lease = AuthorityLease::acquire(&root).unwrap();
        let registry = [
            MigrationStep {
                from: 1,
                to: 2,
                apply: checked_migration,
            },
            MigrationStep {
                from: 2,
                to: 3,
                apply: add_credential_grant_policy,
            },
            MigrationStep {
                from: 3,
                to: 4,
                apply: add_input_capture_tables,
            },
            MigrationStep {
                from: 4,
                to: 5,
                apply: add_input_cleanup_state,
            },
            MigrationStep {
                from: 5,
                to: 6,
                apply: add_job_tables,
            },
        ];
        assert!(open_database_with_migrations(&root, &CorePolicy::default(), &registry).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn locked_sqlite_open_flag_rejects_a_symlinked_filename() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let canonical = std::fs::canonicalize(directory.path()).expect("canonical directory");
        let target = canonical.join("target.sqlite3");
        let link = canonical.join("linked.sqlite3");
        let original = b"target bytes";
        std::fs::write(&target, original).expect("target database bytes");
        symlink(&target, &link).expect("sqlite filename symlink");

        assert!(matches!(
            open_internal_database(&link),
            Err(CoreError::StoreUnavailable)
        ));
        assert_eq!(
            std::fs::read(target).expect("target after SQLite refusal"),
            original
        );
    }

    #[test]
    fn failed_initialization_rolls_back_file_backed_schema_and_markers() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("rollback.sqlite3");
        let mut connection = Connection::open(path).expect("file-backed database");
        connection
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .expect("sqlite policy");

        assert_eq!(
            initialize_schema_with_hook(&mut connection, || Err(CoreError::StoreUnavailable)),
            Err(CoreError::StoreUnavailable)
        );
        let application_id: i64 = connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .expect("application marker");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("schema version");
        let table_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='table'",
                [],
                |row| row.get(0),
            )
            .expect("schema table count");
        assert_eq!(application_id, 0);
        assert_eq!(version, 0);
        assert_eq!(table_count, 0);
    }

    #[test]
    fn native_signal_shutdown_has_a_durable_identity_and_restart_marks_it_interrupted() {
        let mut connection = Connection::open_in_memory().expect("in-memory metadata");
        initialize_schema(&mut connection).expect("initial schema");
        let identity = read_identity(&connection).expect("service identity");
        let operation_id = signal_shutdown(&mut connection, identity.instance_id.clone())
            .expect("signal intent commit");
        let phase: String = connection
            .query_row(
                "SELECT phase FROM internal_shutdowns WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| row.get(0),
            )
            .expect("durable signal operation");
        assert_eq!(phase, "quiescing");

        // The next owner reconciles a process that died before the final barrier.
        initialize_schema(&mut connection).expect("startup recovery");
        let (state, phase): (String, String) = connection
            .query_row(
                "SELECT state,phase FROM internal_shutdowns WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("recovered signal operation");
        assert_eq!(
            (state.as_str(), phase.as_str()),
            ("interrupted", "interrupted")
        );
    }

    #[test]
    fn native_signal_shutdown_completion_commits_its_internal_operation() {
        let mut connection = Connection::open_in_memory().expect("in-memory metadata");
        initialize_schema(&mut connection).expect("initial schema");
        let identity = read_identity(&connection).expect("service identity");
        let operation_id = signal_shutdown(&mut connection, identity.instance_id.clone())
            .expect("signal intent commit");
        complete_shutdown(&mut connection, identity.instance_id).expect("shutdown barrier");
        let (state, phase): (String, String) = connection
            .query_row(
                "SELECT state,phase FROM internal_shutdowns WHERE operation_id=?1",
                [operation_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("completed signal operation");
        assert_eq!(
            (state.as_str(), phase.as_str()),
            ("succeeded", "shutdown_committed")
        );
    }

    #[test]
    fn native_signal_reuses_an_already_accepted_api_shutdown_coordinator() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("signal-race-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let (shutdown_sender, mut shutdown_receiver) = tokio::sync::mpsc::unbounded_channel();
        let store =
            Store::open_with_shutdown(root, lease, &CorePolicy::default(), Some(shutdown_sender))
                .expect("coordinated store");
        let identity = store.identity().expect("service identity");
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client");
        let enrollment_id =
            dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
                .expect("enrollment");
        let secret = [87_u8; 32];
        let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
        store
            .enroll(VerifiedEnrollment::new(
                current_owner_identity().expect("owner"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            ))
            .expect("enroll stop client");
        let context = store
            .authenticate(client_id, digest)
            .expect("active stop grant");
        store
            .request_shutdown(
                context,
                identity.instance_id.clone(),
                IdempotencyKey::parse("signal-race-api-key-1").expect("idempotency key"),
            )
            .expect("API shutdown acceptance");
        let accepted_deadline = shutdown_receiver
            .try_recv()
            .expect("accepted API shutdown woke coordinator");
        let signal_deadline = store
            .signal_shutdown(identity.instance_id, 5_000)
            .expect("native signal reuses active coordinator");
        assert_eq!(signal_deadline, accepted_deadline);
        drop(store);

        let database = Connection::open(path.join(DATABASE_NAME)).expect("metadata database");
        let internal_rows: i64 = database
            .query_row("SELECT count(*) FROM internal_shutdowns", [], |row| {
                row.get(0)
            })
            .expect("internal signal operations");
        assert_eq!(internal_rows, 0, "the race must not create a second intent");
    }

    #[test]
    fn failed_migration_keeps_consistent_backup_and_original_store() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("migration-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("create v1 store");
        drop(store);

        let root = OwnedRoot::open(&path, RootPurpose::EngineData).expect("reopen root");
        let _lease = AuthorityLease::acquire(&root).expect("reacquire authority");
        let mut connection = Connection::open(path.join(DATABASE_NAME)).expect("open v1");
        let migrations = [
            MigrationStep {
                from: SCHEMA_VERSION,
                to: SCHEMA_VERSION + 1,
                apply: add_temporary_migration_table,
            },
            MigrationStep {
                from: SCHEMA_VERSION + 1,
                to: SCHEMA_VERSION + 2,
                apply: injected_migration_failure,
            },
        ];
        assert_eq!(
            run_migrations(&mut connection, &root, &migrations),
            Err(CoreError::StoreUnavailable)
        );
        let original_version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("original version");
        assert_eq!(original_version, SCHEMA_VERSION);
        let temporary_table_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='temporary_migration_probe'",
                [],
                |row| row.get(0),
            )
            .expect("migration table count");
        assert_eq!(temporary_table_count, 0);

        let backup_name = recovery_backup_for_version(SCHEMA_VERSION + 2).unwrap();
        let backup_path = root.path_for_native_vfs(&backup_name);
        assert!(
            root.file_metadata(&backup_name)
                .expect("protected backup")
                .length
                > 0
        );
        let backup = Connection::open(backup_path).expect("retained backup");
        let integrity: String = backup
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("backup integrity");
        assert_eq!(integrity, "ok");
        let backup_version: i64 = backup
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("backup version");
        assert_eq!(backup_version, SCHEMA_VERSION);
    }

    #[test]
    fn schema_v1_store_migrates_additively_before_shutdown_recovery() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root_path = directory.path().join("legacy-root");
        let root =
            OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("protected root");
        let lease = AuthorityLease::acquire(&root).expect("initial authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("initial store");
        let identity = store.identity().expect("initial identity");
        drop(store);

        let root =
            OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("reopen root");
        let database_path =
            root.path_for_native_vfs(&RelativePath::parse(DATABASE_NAME).expect("database path"));
        let connection = Connection::open(&database_path).expect("legacy database");
        assert_eq!(
            read_identity(&connection).expect("legacy identity"),
            identity
        );
        connection
            .execute_batch(
                "DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs;
                 DROP TABLE input_upload_reservations;
                 DROP TABLE internal_shutdowns;
                 ALTER TABLE credentials DROP COLUMN grant_policy;
                 PRAGMA user_version=1;",
            )
            .expect("shape schema-v1 fixture");
        drop(connection);

        let lease = AuthorityLease::acquire(&root).expect("legacy authority");
        let store = Store::open(root, lease, &CorePolicy::default())
            .expect("production startup migrates before recovery");
        let migrated_identity = store.identity().expect("migrated identity");
        drop(store);

        let connection = Connection::open(&database_path).expect("migrated database");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("migrated version");
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(migrated_identity.installation_id, identity.installation_id);
        assert_ne!(migrated_identity.instance_id, identity.instance_id);
        assert_eq!(
            read_identity(&connection).expect("recovered identity"),
            migrated_identity
        );
        let table_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='internal_shutdowns'",
                [],
                |row| row.get(0),
            )
            .expect("internal shutdown table");
        assert_eq!(table_count, 1);
        let backup = root_path.join(
            recovery_backup_for_version(SCHEMA_VERSION)
                .unwrap()
                .as_str(),
        );
        let backup = Connection::open(backup).expect("retained v1 recovery backup");
        let backup_version: i64 = backup
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("backup version");
        assert_eq!(backup_version, 1);
    }

    #[test]
    fn shutdown_request_is_durable_idempotent_and_bound_to_its_instance() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("shutdown-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
        let identity = store.identity().expect("identity");
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
        let enrollment_id =
            dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
                .expect("enrollment id");
        let secret = [73_u8; 32];
        let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
        store
            .enroll(VerifiedEnrollment::new(
                current_owner_identity().expect("owner"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            ))
            .expect("enroll stop client");
        let context = store
            .authenticate(client_id, digest)
            .expect("active stop grant");
        let key = IdempotencyKey::parse("stop-test-key-0001").expect("idempotency key");
        let accepted = store
            .request_shutdown(context.clone(), identity.instance_id.clone(), key.clone())
            .expect("durably accepted stop");
        assert!(!accepted.replayed);
        assert_eq!(accepted.state, OperationState::Queued);
        assert_eq!(
            store
                .show_operation(context.clone(), accepted.operation_id.clone())
                .expect("accepted operation phase")
                .phase,
            "running"
        );
        assert_eq!(store.revoke_self(context.clone()), Err(CoreError::Busy));

        let replayed = store
            .request_shutdown(context.clone(), identity.instance_id.clone(), key.clone())
            .expect("exact replay");
        assert!(replayed.replayed);
        assert_eq!(replayed.operation_id, accepted.operation_id);
        assert_eq!(replayed.accepted_at_ms, accepted.accepted_at_ms);

        let other_instance =
            InstanceId::parse("eng_ffffffffffffffffffffffffffffffff").expect("other instance");
        assert_eq!(
            store.request_shutdown(context.clone(), other_instance, key.clone()),
            Err(CoreError::Conflict)
        );

        // Closing the actor without the completion barrier exercises restart
        // reconciliation in-process; abrupt process death is covered only by
        // the test-owned lifecycle process acceptance.
        drop(store);

        let root = OwnedRoot::open(&path, RootPurpose::EngineData).expect("reopen root");
        let lease = AuthorityLease::acquire(&root).expect("reopened authority");
        let restarted = Store::open(root, lease, &CorePolicy::default()).expect("restart store");
        let current = restarted.identity().expect("new instance");
        assert_ne!(current.instance_id, identity.instance_id);
        let restarted_context = restarted
            .authenticate(
                ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id"),
                TokenDigest::new(sha2::Sha256::digest(secret).into()),
            )
            .expect("credential survives restart");
        let old_operation = restarted
            .request_shutdown(
                restarted_context.clone(),
                identity.instance_id.clone(),
                key.clone(),
            )
            .expect("old instance replay");
        assert_eq!(old_operation.state, OperationState::Interrupted);
        assert!(old_operation.replayed);
        assert_eq!(
            restarted
                .request_shutdown(restarted_context.clone(), current.instance_id.clone(), key,),
            Err(CoreError::Conflict)
        );
        let current_key = IdempotencyKey::parse("stop-test-key-0002").expect("current key");
        let accepted_current = restarted
            .request_shutdown(
                restarted_context.clone(),
                current.instance_id.clone(),
                current_key.clone(),
            )
            .expect("new instance has a new operation");
        assert!(!accepted_current.replayed);
        restarted
            .complete_shutdown(current.instance_id.clone())
            .expect("current instance shutdown completion");
        let committed = restarted
            .show_operation(
                restarted_context.clone(),
                accepted_current.operation_id.clone(),
            )
            .expect("committed shutdown phase");
        assert_eq!(committed.phase, "shutdown_committed");
        let completed = restarted
            .request_shutdown(restarted_context, current.instance_id, current_key)
            .expect("completed request replay");
        assert_eq!(completed.state, OperationState::Succeeded);
        assert!(completed.replayed);
        drop(restarted);
    }

    #[test]
    fn shutdown_fingerprint_uses_the_accepted_canonical_preimage() {
        let instance =
            InstanceId::parse("eng_0123456789abcdef0123456789abcdef").expect("instance id");
        let preimage = format!("core-shutdown-v1\n{}\n", instance.as_str());
        let expected: [u8; 32] = sha2::Sha256::digest(preimage.as_bytes()).into();
        assert_eq!(shutdown_fingerprint(&instance), expected);
    }

    #[test]
    fn operation_history_limit_allows_replay_but_rejects_new_shutdown_rows() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("operation-cap-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
        let identity = store.identity().expect("identity");
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client");
        let enrollment_id =
            dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
                .expect("enrollment");
        let digest = TokenDigest::new(sha2::Sha256::digest([73_u8; 32]).into());
        store
            .enroll(VerifiedEnrollment::new(
                current_owner_identity().expect("owner"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            ))
            .expect("enroll");
        let context = store.authenticate(client_id, digest).expect("authenticate");
        let replay_key = IdempotencyKey::parse("operation-cap-replay-01").expect("key");
        let accepted = store
            .request_shutdown(
                context.clone(),
                identity.instance_id.clone(),
                replay_key.clone(),
            )
            .expect("first acceptance");
        store
            .seed_operation_history((MAX_CORE_OPERATION_ROWS - 1) as usize)
            .expect("fill durable operation history");
        let replay = store
            .request_shutdown(context.clone(), identity.instance_id.clone(), replay_key)
            .expect("exact replay at capacity");
        assert!(replay.replayed);
        assert_eq!(replay.operation_id, accepted.operation_id);
        assert_eq!(
            store.request_shutdown(
                context,
                identity.instance_id,
                IdempotencyKey::parse("operation-cap-new-key-01").expect("new key"),
            ),
            Err(CoreError::LimitReached),
        );
    }

    #[test]
    fn dropping_shutdown_response_waiter_does_not_strand_committed_intent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("shutdown-coordinator-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let (intent_sender, mut intent_receiver) = tokio::sync::mpsc::unbounded_channel();
        let store =
            Store::open_with_shutdown(root, lease, &CorePolicy::default(), Some(intent_sender))
                .expect("store with engine coordinator");
        let identity = store.identity().expect("identity");
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
        let enrollment_id =
            dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
                .expect("enrollment id");
        let digest = TokenDigest::new(sha2::Sha256::digest([73_u8; 32]).into());
        store
            .enroll(VerifiedEnrollment::new(
                current_owner_identity().expect("owner"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            ))
            .expect("enroll stop client");
        let context = store.authenticate(client_id, digest).expect("active grant");
        let key = IdempotencyKey::parse("shutdown-cancel-window-1").expect("shutdown key");

        // Hold the actor immediately before transactional acceptance so the
        // response waiter disappears while the commit is still in flight.
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let (configured_sender, configured_receiver) = mpsc::sync_channel(1);
        store
            .sender
            .send(Command::PauseNextShutdown(
                started_sender,
                release_receiver,
                configured_sender,
            ))
            .expect("configure internal acceptance barrier");
        configured_receiver
            .recv()
            .expect("actor installed internal acceptance barrier");

        // This dropped reply models HTTP task cancellation. The synchronous
        // actor command remains owned by the engine and finishes its commit.
        let (receipt_sender, receipt_receiver) = mpsc::sync_channel(1);
        store
            .sender
            .try_send(Command::Shutdown(
                context.clone(),
                identity.instance_id.clone(),
                key.clone(),
                receipt_sender,
            ))
            .expect("queue shutdown acceptance");
        started_receiver
            .recv()
            .expect("actor paused during shutdown acceptance");
        drop(receipt_receiver);
        release_sender
            .send(())
            .expect("release internal acceptance barrier");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let first_deadline = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), intent_receiver.recv())
                .await
                .expect("committed shutdown wakes the coordinator")
                .expect("coordinator remains alive")
        });

        let replay = store
            .request_shutdown(context.clone(), identity.instance_id.clone(), key)
            .expect("exact queued replay");
        assert!(replay.replayed);
        assert_eq!(replay.state, OperationState::Running);
        let snapshot = store
            .show_operation(context, replay.operation_id.clone())
            .expect("operation snapshot");
        assert_eq!(snapshot.state, OperationState::Running);
        assert_eq!(snapshot.phase, "quiescing");
        let replay_deadline = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), intent_receiver.recv())
                .await
                .expect("queued replay re-arms coordinator")
                .expect("coordinator remains alive")
        });
        assert_eq!(
            replay_deadline, first_deadline,
            "replay must not reset shutdown budget"
        );
    }

    #[test]
    fn injected_sqlite_page_limit_returns_failure_without_committing_partial_enrollment() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("limited-store");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
        let identity = store.identity().expect("identity");
        let owner = current_owner_identity().expect("owner");
        store
            .limit_database_pages_to_current_plus_one()
            .expect("test-only SQLite page limit");

        let mut failed = None;
        for index in 0..2_048_u32 {
            let client_id =
                ClientId::parse(format!("cli_{index:032x}")).expect("test client identity");
            let enrollment_id = dissect3d_api::EnrollmentId::parse(format!("enr_{index:032x}"))
                .expect("test enrollment identity");
            let digest = TokenDigest::new([index as u8; 32]);
            match store.enroll(VerifiedEnrollment::new(
                owner.clone(),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            )) {
                Ok(_) => {}
                Err(CoreError::StoreUnavailable) => {
                    failed = Some((client_id, digest));
                    break;
                }
                Err(error) => panic!("unexpected injected page-limit result: {error:?}"),
            }
        }
        let (client_id, digest) = failed.expect("SQLite page limit must be reached");
        assert!(matches!(
            store.authenticate(client_id, digest),
            Err(CoreError::Unauthorized)
        ));
        drop(store);

        let database = Connection::open(path.join(DATABASE_NAME)).expect("SQLite database");
        let integrity: String = database
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity check");
        assert_eq!(integrity, "ok");
    }

    #[test]
    fn injected_shutdown_precommit_failure_returns_no_receipt_and_allows_exact_retry() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("shutdown-fault-root");
        let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
        let lease = AuthorityLease::acquire(&root).expect("authority");
        let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
        let identity = store.identity().expect("identity");
        let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
        let enrollment_id =
            dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
                .expect("enrollment id");
        let secret = [73_u8; 32];
        let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
        store
            .enroll(VerifiedEnrollment::new(
                current_owner_identity().expect("owner"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                enrollment_id,
                client_id.clone(),
                digest.clone(),
            ))
            .expect("enroll stop client");
        let context = store
            .authenticate(client_id, digest)
            .expect("active shutdown grant");
        let key = IdempotencyKey::parse("shutdown-fault-key-01").expect("shutdown key");
        store
            .fail_next_shutdown_commit()
            .expect("arm one-shot precommit failure");

        assert!(matches!(
            store.request_shutdown(context.clone(), identity.instance_id.clone(), key.clone()),
            Err(CoreError::StoreUnavailable)
        ));
        let accepted = store
            .request_shutdown(context, identity.instance_id.clone(), key)
            .expect("exact retry after rolled-back transaction");
        assert!(!accepted.replayed);
        assert_eq!(accepted.state, OperationState::Queued);
        drop(store);

        let database = Connection::open(path.join(DATABASE_NAME)).expect("SQLite database");
        let count: i64 = database
            .query_row(
                "SELECT count(*) FROM core_operations WHERE kind='engine.shutdown'",
                [],
                |row| row.get(0),
            )
            .expect("operation count");
        assert_eq!(count, 1, "failed transaction must leave no duplicate row");
        let integrity: String = database
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("integrity check");
        assert_eq!(integrity, "ok");
    }
}

#[cfg(all(test, unix))]
#[path = "store/input_cleanup_tests.rs"]
mod input_cleanup_tests;
#[cfg(test)]
#[path = "store/submission_tests.rs"]
mod submission_tests;

#[cfg(all(test, unix))]
mod job_tests;
