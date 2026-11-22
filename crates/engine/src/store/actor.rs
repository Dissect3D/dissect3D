//! The store actor: the typed command protocol and the loop that owns the
//! SQLite connection and authority lease on its dedicated thread.

use super::*;

pub(super) enum Command {
    #[cfg(unix)]
    ExecutionRead(execution_reads::ReadCommand),
    #[allow(dead_code, reason = "private execution consumers follow in WE-P04/06")]
    Execution(execution::ExecutionCommand),
    #[allow(dead_code, reason = "private result consumers follow in RP-P03/WE-P06")]
    Results(results::ResultCommand),
    #[cfg(all(test, unix, feature = "test-support"))]
    JobLimits(
        admission::AcceptanceLimits,
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
    ReadSubmission(
        AuthContext,
        IdempotencyKey,
        crate::submission::equivalence::SubmittedJobRequest,
        SyncSender<Result<submission::ReadState, crate::domain::SubmissionError>>,
    ),
    #[cfg(unix)]
    FinishSubmission(
        AuthContext,
        IdempotencyKey,
        crate::submission::equivalence::SubmittedJobRequest,
        Option<Arc<crate::submission::admission::AdmissionCandidate>>,
        Box<submission::Prepared>,
        SyncSender<
            Result<
                Option<Option<dissect3d_api::AcceptanceReceipt>>,
                crate::domain::SubmissionError,
            >,
        >,
    ),
    #[cfg(unix)]
    ReadRetry(
        AuthContext,
        IdempotencyKey,
        dissect3d_api::JobId,
        SyncSender<Result<retry::RetryRead, crate::domain::SubmissionError>>,
    ),
    #[cfg(unix)]
    FinishRetry(
        AuthContext,
        IdempotencyKey,
        dissect3d_api::JobId,
        Box<retry::RetryPrepared>,
        SyncSender<
            Result<Option<dissect3d_api::ExecutionAcceptance>, crate::domain::SubmissionError>,
        >,
    ),
    #[cfg(unix)]
    ShowJob(
        AuthContext,
        dissect3d_api::JobId,
        mpsc::SyncSender<Result<dissect3d_api::JobSnapshot, crate::domain::SubmissionError>>,
    ),
    #[cfg(unix)]
    ListJobs(
        AuthContext,
        dissect3d_api::JobsQuery,
        mpsc::SyncSender<Result<dissect3d_api::JobPage, crate::domain::SubmissionError>>,
    ),
    #[cfg(unix)]
    JobAuditBatch(
        String,
        mpsc::SyncSender<Result<Vec<jobs::AuditEntry>, crate::domain::SubmissionError>>,
    ),
    #[cfg(unix)]
    MarkJobInputFault(
        InputId,
        mpsc::SyncSender<Result<(), crate::domain::SubmissionError>>,
    ),
    CompleteShutdown(InstanceId, mpsc::SyncSender<Result<(), CoreError>>),
    SignalShutdown(
        InstanceId,
        u32,
        mpsc::SyncSender<Result<Instant, CoreError>>,
    ),
    #[cfg(all(unix, test, feature = "test-support"))]
    FailNextJobCommit(mpsc::SyncSender<Result<(), CoreError>>),
    AuthorizeExecution(
        reauthorization::VerifiedAuthorization,
        SyncSender<Result<reauthorization::AuthorizationReceipt, CoreError>>,
    ),
    Close,
    #[cfg(all(test, unix, feature = "test-support"))]
    PauseExecutionQueue(SyncSender<()>, Receiver<()>),
    #[cfg(test)]
    LimitDatabasePages(mpsc::SyncSender<Result<(), CoreError>>),
    #[cfg(test)]
    FailNextShutdownCommit,
    #[cfg(test)]
    PauseNextShutdown(mpsc::SyncSender<()>, Receiver<()>, mpsc::SyncSender<()>),
    #[cfg(test)]
    SeedOperationHistory(usize, mpsc::SyncSender<Result<(), CoreError>>),
}

/// How a handled command affects in-flight caller-side admission preparations.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreparationEffect {
    /// Changes no fact behind a preparation, or only facts `finish` rechecks
    /// in SQL or that can only make the free-space observation conservative.
    Keeps,
    /// May change disk usage the caller-side free-space observation cannot see.
    Invalidates,
}

#[cfg(unix)]
impl Command {
    /// Explicit classification; unknown and new commands invalidate by default.
    fn preparation_effect(&self) -> PreparationEffect {
        use PreparationEffect::{Invalidates, Keeps};
        match self {
            // Read-only commands.
            Command::Identity(_)
            | Command::Authenticate(..)
            | Command::Snapshot(..)
            | Command::ShowOperation(..)
            | Command::ExecutionRead(_)
            | Command::ReadSubmission(..)
            | Command::ReadRetry(..)
            | Command::ShowJob(..)
            | Command::ListJobs(..)
            | Command::InputFileKnown(..)
            | Command::JobAuditBatch(..) => Keeps,
            // In-memory pins plus a forward clock write; finish rechecks expiry
            // with its own clock observation.
            Command::PinVerifiedInputs(..) => Keeps,
            // A new reservation is charged in SQL when finish sums reservations.
            Command::ReserveUpload(..) => Keeps,
            // These only free disk (staging/input files are removed first), so an
            // older observation can only understate free space. For abandonment
            // that order is the caller's: `inputs.rs::cleanup_incomplete` removes the
            // staging file and calls `abandon_upload` only after removal or NotFound.
            Command::AbandonUpload(..)
            | Command::ClaimInputCleanup(..)
            | Command::ConfirmInputCleanup(..) => Keeps,
            // A committed sibling is charged one growth allowance through
            // `AdmissionEpoch::admissions`; the handler escalates an uncertain commit.
            Command::FinishSubmission(..) | Command::FinishRetry(..) => Keeps,
            // `CompleteUpload` drops the reservation that covered bytes which may
            // have landed after the observation. Everything else, including test
            // commands and future variants, invalidates by default.
            _ => Invalidates,
        }
    }
}

pub(super) fn actor(
    root: Arc<OwnedRoot>,
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
    let mut job_limits = admission::AcceptanceLimits::default();
    #[cfg(all(unix, not(all(test, feature = "test-support"))))]
    let job_limits = admission::AcceptanceLimits::default();
    let _ = ready.send(Ok(()));
    let mut stopping = false;
    let mut live_attempts = execution::LiveAttempts::default();
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
    #[cfg(unix)]
    let mut preparation_epoch = admission::AdmissionEpoch::default();
    while let Ok(command) = receiver.recv() {
        // Fresh admission compares this epoch with its read snapshot. The
        // generation moves after a handler whose command may have changed disk
        // usage that the caller-side free-space observation cannot recheck in SQL.
        #[cfg(unix)]
        let mut invalidates_preparation =
            command.preparation_effect() == PreparationEffect::Invalidates;
        match command {
            #[cfg(unix)]
            Command::ExecutionRead(command) => {
                command.handle(&connection, policy.control_response_bytes)
            }
            #[cfg(all(test, unix, feature = "test-support"))]
            Command::PauseExecutionQueue(entered, resume) => {
                let _ = entered.send(());
                let _ = resume.recv_timeout(Duration::from_secs(5));
            }
            Command::Execution(command) => live_attempts.handle(&mut connection, command, stopping),
            Command::Results(command) => results::handle(&mut connection, command, stopping),
            Command::AuthorizeExecution(request, reply) => {
                let result = if stopping || cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    reauthorization::authorize(&mut connection, request)
                };
                let _ = reply.send(result);
            }
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
            #[cfg(all(test, unix, feature = "test-support"))]
            Command::JobLimits(limits, reply) => {
                job_limits = limits;
                let _ = reply.send(Ok(()));
            }
            #[cfg(unix)]
            Command::ReadSubmission(auth, key, request, reply) => {
                let _ = reply.send(submission::read_state(
                    &mut connection,
                    &auth,
                    &key,
                    &request,
                    preparation_epoch,
                ));
            }
            #[cfg(unix)]
            Command::FinishSubmission(auth, key, request, candidate, prepared, reply) => {
                #[cfg(all(test, feature = "test-support"))]
                let fail_commit = fail_next_job_commit;
                #[cfg(not(all(test, feature = "test-support")))]
                let fail_commit = false;
                let result = submission::finish(
                    &mut connection,
                    submission::ActorTurn {
                        root: &root,
                        epoch: preparation_epoch,
                        policy: admission::AcceptancePolicy {
                            stopping,
                            fail_commit,
                            response_limit: policy.control_response_bytes,
                            limits: job_limits,
                        },
                    },
                    submission::Finish {
                        auth,
                        key,
                        submitted: request,
                        candidate: candidate.as_deref(),
                        prepared: *prepared,
                    },
                );
                #[cfg(all(test, feature = "test-support"))]
                if !matches!(result, Ok(None)) {
                    fail_next_job_commit = false;
                }
                // Stale, probe-only, replay and rejected results roll back or
                // change no admission fact. A committed fresh acceptance is charged
                // to later finishes; a store failure may follow an unknown COMMIT.
                match &result {
                    Ok(Some(Some(receipt))) if !receipt.replayed => {
                        preparation_epoch.admissions = preparation_epoch.admissions.wrapping_add(1);
                    }
                    Err(error) if error.code == dissect3d_api::ErrorCode::StoreUnavailable => {
                        invalidates_preparation = true;
                    }
                    _ => {}
                }
                let _ = reply.send(result);
            }
            #[cfg(unix)]
            Command::ReadRetry(auth, key, source, reply) => {
                let _ = reply.send(retry::read_retry(
                    &mut connection,
                    &auth,
                    &key,
                    &source,
                    preparation_epoch,
                ));
            }
            #[cfg(unix)]
            Command::FinishRetry(auth, key, source, prepared, reply) => {
                #[cfg(all(test, feature = "test-support"))]
                let fail_commit = fail_next_job_commit;
                #[cfg(not(all(test, feature = "test-support")))]
                let fail_commit = false;
                let result = retry::finish_retry(
                    &mut connection,
                    submission::ActorTurn {
                        root: &root,
                        epoch: preparation_epoch,
                        policy: admission::AcceptancePolicy {
                            stopping,
                            fail_commit,
                            response_limit: policy.control_response_bytes,
                            limits: job_limits,
                        },
                    },
                    retry::RetryFinish {
                        auth,
                        key,
                        source,
                        prepared: *prepared,
                    },
                );
                #[cfg(all(test, feature = "test-support"))]
                if !matches!(result, Ok(None)) {
                    fail_next_job_commit = false;
                }
                // As for submission: a committed fresh retry is charged to later
                // finishes; a store failure may follow an unknown COMMIT.
                match &result {
                    Ok(Some(receipt)) if !receipt.replayed => {
                        preparation_epoch.admissions = preparation_epoch.admissions.wrapping_add(1);
                    }
                    Err(error) if error.code == dissect3d_api::ErrorCode::StoreUnavailable => {
                        invalidates_preparation = true;
                    }
                    _ => {}
                }
                let _ = reply.send(result);
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
        #[cfg(unix)]
        if invalidates_preparation {
            preparation_epoch.generation = preparation_epoch.generation.wrapping_add(1);
        }
    }
    drop(connection);
    // The authority lease is dropped only after SQLite has closed.
}
