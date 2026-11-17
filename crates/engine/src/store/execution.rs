//! Store-owned execution transactions. No scheduler or public activation lives here.
use super::*;
use dissect3d_api::JobId;
use std::collections::{BTreeSet, HashMap};

/// This clock is never serialized or reconstructed after restart.
#[derive(Debug)]
pub(crate) struct AttemptTiming {
    started: Instant,
    deadline: Option<Instant>,
}
impl AttemptTiming {
    #[cfg(test)]
    pub(crate) fn for_validation_test() -> Self {
        Self {
            started: Instant::now(),
            deadline: None,
        }
    }
    /// Test-only record, as the Store would register it at dispatch.
    #[cfg(test)]
    pub(crate) fn for_supervision_test(timeout: Option<Duration>) -> Self {
        let started = Instant::now();
        Self {
            started,
            deadline: timeout.map(|t| started + t),
        }
    }
    pub(crate) fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
    pub(crate) fn started(&self) -> Instant {
        self.started
    }
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[derive(Clone)]
pub(crate) struct DispatchRequest {
    pub(crate) job_id: JobId,
    pub(crate) expected_revision: i64,
    /// Exact captured bytes obtained from Store, never a newly resolved profile.
    pub(crate) resolved_json: String,
    pub(crate) resources: Vec<String>,
}
impl DispatchRequest {
    fn validate(&self) -> Result<(), CoreError> {
        if self.expected_revision < 1
            || self.expected_revision == i64::MAX
            || self.resolved_json.len() > 262_144
            || self.resources.is_empty()
            || self.resources.len() > 16
            || self.resources.iter().any(|r| {
                r.is_empty()
                    || r.len() > 128
                    || !r
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            })
        {
            return Err(CoreError::Conflict);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub(crate) struct DispatchRecord {
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: String,
    pub(crate) session_id: String,
    pub(crate) grant_id: String,
    pub(crate) resolved_json: String,
    pub(crate) resources: Vec<String>,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) timing: Arc<AttemptTiming>,
}
#[derive(Default)]
pub(super) struct LiveAttempts(HashMap<String, DispatchRecord>);

pub(super) enum ExecutionCommand {
    Dispatch(
        DispatchRequest,
        SyncSender<Result<DispatchRecord, CoreError>>,
    ),
    Timing(String, SyncSender<Result<Arc<AttemptTiming>, CoreError>>),
    Cancel(
        AuthContext,
        JobId,
        SyncSender<Result<&'static str, CoreError>>,
    ),
    Cleanup(
        super::cleanup::CleanupReport,
        SyncSender<Result<super::cleanup::CleanupReceipt, CoreError>>,
    ),
    Finalize(
        super::finalize::AttemptFinalization,
        SyncSender<Result<super::finalize::FinalizationReceipt, CoreError>>,
    ),
    Observe(
        super::finalize::AttemptObservation,
        SyncSender<Result<super::cleanup::CleanupReceipt, CoreError>>,
    ),
}
impl Store {
    // WE-P04/06 must supply fresh readiness, input-integrity and eligibility checks
    // before using this private seam. No current service calls it.
    pub(crate) fn dispatch_attempt(
        &self,
        request: DispatchRequest,
    ) -> Result<DispatchRecord, CoreError> {
        request.validate()?;
        self.request(|reply| Command::Execution(ExecutionCommand::Dispatch(request, reply)))
    }
    pub(crate) fn cancel_execution_job(
        &self,
        auth: AuthContext,
        job: JobId,
    ) -> Result<&'static str, CoreError> {
        self.request(|reply| Command::Execution(ExecutionCommand::Cancel(auth, job, reply)))
    }
    pub(crate) fn attempt_timing(
        &self,
        attempt_id: String,
    ) -> Result<Arc<AttemptTiming>, CoreError> {
        if attempt_id.len() != 36 {
            return Err(CoreError::NotFound);
        }
        self.request(|reply| Command::Execution(ExecutionCommand::Timing(attempt_id, reply)))
    }
}
impl LiveAttempts {
    /// Drop a finished attempt's live record; only confirmed cleanup calls this.
    pub(super) fn forget(&mut self, attempt_id: &str) {
        self.0.remove(attempt_id);
    }
    pub(super) fn handle(
        &mut self,
        connection: &mut Connection,
        command: ExecutionCommand,
        stopping: bool,
    ) {
        match command {
            ExecutionCommand::Dispatch(request, reply) => {
                let result = if stopping || cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    dispatch(connection, self, request)
                };
                // Receiver loss cannot remove the committed attempt or its clock.
                let _ = reply.send(result);
            }
            ExecutionCommand::Cancel(auth, job, reply) => {
                let result = if stopping || cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    cancel(connection, &auth, &job)
                };
                let _ = reply.send(result);
            }
            // Cleanup facts are recorded even while stopping: shutdown and
            // recovery must be able to establish them (WE-005).
            ExecutionCommand::Cleanup(report, reply) => {
                let result = if cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    super::cleanup::record_cleanup(connection, self, report)
                };
                let _ = reply.send(result);
            }
            // Shutdown records `interrupted` outcomes, so finalization also
            // runs while stopping (WE-005).
            ExecutionCommand::Finalize(finalization, reply) => {
                let result = if cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    super::finalize::finalize(connection, self, finalization)
                };
                let _ = reply.send(result);
            }
            ExecutionCommand::Observe(observation, reply) => {
                let result = if stopping || cfg!(windows) {
                    Err(CoreError::Busy)
                } else {
                    super::finalize::observe(connection, observation)
                };
                let _ = reply.send(result);
            }
            ExecutionCommand::Timing(id, reply) => {
                let _ = reply.send(
                    self.0
                        .get(&id)
                        .map(|r| r.timing.clone())
                        .ok_or(CoreError::NotFound),
                );
            }
        }
    }
}
pub(super) fn dispatch(
    db: &mut Connection,
    live: &mut LiveAttempts,
    mut request: DispatchRequest,
) -> Result<DispatchRecord, CoreError> {
    request.validate()?;
    let set: BTreeSet<_> = request.resources.iter().collect();
    if set.len() != request.resources.len() {
        return Err(CoreError::Conflict);
    }
    request.resources.sort();
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let identity = read_identity(&tx)?;
    type Row = (String, i64, String, Option<i64>, String, String);
    let row: Option<Row> = sql(tx
        .query_row(
            "SELECT e.state,e.snapshot_revision,j.resolved_json,e.timeout_ms,j.storage_status,j.client_id
             FROM job_execution e JOIN jobs j USING(job_id)
             WHERE e.job_id=?1",
            [request.job_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional())?;
    let (state, revision, resolved, timeout, status, _creator) = row.ok_or(CoreError::NotFound)?;
    if resolved != request.resolved_json || status != "verified" {
        return Err(CoreError::Conflict);
    }
    let timeout = timeout
        .map(u64::try_from)
        .transpose()
        .map_err(|_| CoreError::InvalidStore)?;
    // A duplicate command can retrieve only the existing live, uncanceled attempt.
    if state == "running" {
        let record = live
            .0
            .values()
            .find(|r| r.job_id == request.job_id)
            .ok_or(CoreError::Conflict)?;
        if record.resources != request.resources || revision != request.expected_revision + 1 {
            return Err(CoreError::Conflict);
        }
        return Ok(record.clone());
    }
    if state != "queued" || revision != request.expected_revision {
        return Err(CoreError::Conflict);
    }
    if live.0.len() >= 128 {
        return Err(CoreError::LimitReached);
    }
    live.0.try_reserve(1).map_err(|_| CoreError::LimitReached)?;
    let attempt = random_id("att_")?;
    let session = random_id("ses_")?;
    let grant = random_id("grt_")?;
    let now = now_ms()?;
    sql(tx.execute(
        "INSERT INTO job_attempts(attempt_id,job_id,instance_id,session_id,grant_id,dispatched_at_ms,
                                  cleanup_status)
         VALUES(?1,?2,?3,?4,?5,?6,'pending')",
        rusqlite::params![
            attempt,
            request.job_id.as_str(),
            identity.instance_id.as_str(),
            session,
            grant,
            now
        ],
    ))?;
    for resource in &request.resources {
        let held: bool = sql(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM resource_reservations WHERE resource_id=?1 AND released=0)",
            [resource],
            |r| r.get(0),
        ))?;
        if held {
            return Err(CoreError::Busy);
        }
        sql(tx.execute(
            "INSERT INTO resource_reservations(attempt_id,resource_id) VALUES(?1,?2)",
            rusqlite::params![attempt, resource],
        ))?;
    }
    sql(tx.execute(
        "UPDATE job_execution
         SET state='running',phase='launching',snapshot_revision=snapshot_revision+1,
             cleanup_status='pending',updated_at_ms=?2
         WHERE job_id=?1",
        rusqlite::params![request.job_id.as_str(), now],
    ))?;
    record_event(&tx, request.job_id.as_str())?;
    sql(tx.commit())?;
    // The successful durable COMMIT is the linearization boundary. Do nothing
    // between it and sampling the clock; replies/launch never create a new timer.
    let started = Instant::now();
    let timing = Arc::new(AttemptTiming {
        started,
        deadline: timeout.map(|ms| started + Duration::from_millis(ms)),
    });
    let record = DispatchRecord {
        job_id: request.job_id,
        attempt_id: attempt.clone(),
        session_id: session,
        grant_id: grant,
        resolved_json: resolved,
        resources: request.resources,
        timeout_ms: timeout,
        timing,
    };
    live.0.insert(attempt, record.clone());
    Ok(record)
}

/// Per-job persisted event history bound (ENG-029, ENG-046). Pruning drops the
/// oldest events first and never the newest; job records hold the authoritative
/// facts, so retention never erases terminal, cancellation or cleanup state.
#[derive(Clone, Copy, Debug)]
pub(super) struct EventRetention {
    /// Retained revisions per job.
    pub(super) revisions: i64,
    /// Retained `snapshot_json` bytes per job (`job_event_history_bytes_max`),
    /// separate from the admission bound `job_metadata_bytes_max`.
    pub(super) bytes: i64,
}
pub(super) const EVENT_RETENTION: EventRetention = EventRetention {
    revisions: 256,
    bytes: 262_144,
};
/// Write-side bounds, equal to what the execution reader enforces.
pub(super) const PROGRESS_JSON_BYTES_MAX: usize = 16_384;
pub(super) const SAFE_CODE_BYTES_MAX: usize = 128;

/// A safe engine-owned code (cleanup reason, outcome): 1..=128 bytes of
/// `[a-z0-9_.]`, never a raw path, upstream string or input text.
pub(super) fn is_safe_code(value: &str) -> bool {
    (1..=SAFE_CODE_BYTES_MAX).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

pub(super) fn record_event(tx: &Transaction<'_>, job: &str) -> Result<(), CoreError> {
    record_event_within(tx, job, EVENT_RETENTION)
}

/// Insert the current snapshot's event and prune in the same transaction.
pub(super) fn record_event_within(
    tx: &Transaction<'_>,
    job: &str,
    retention: EventRetention,
) -> Result<(), CoreError> {
    // Every transition records its event here, so this rejects an oversized
    // field from any writer before COMMIT; the caller's transaction rolls back.
    let bounded: bool = sql(tx.query_row(
        "SELECT (progress_json IS NULL OR length(CAST(progress_json AS BLOB))<=?2)
            AND (cleanup_reason IS NULL OR length(CAST(cleanup_reason AS BLOB))<=?3)
            AND (outcome_code IS NULL OR length(CAST(outcome_code AS BLOB))<=?3)
         FROM job_execution WHERE job_id=?1",
        rusqlite::params![
            job,
            PROGRESS_JSON_BYTES_MAX as i64,
            SAFE_CODE_BYTES_MAX as i64
        ],
        |r| r.get(0),
    ))?;
    if !bounded {
        return Err(CoreError::Conflict);
    }
    sql(tx.execute(
        "INSERT INTO job_events
         SELECT job_id,snapshot_revision,
                json_object('snapshot_revision',snapshot_revision,'state',state,'phase',phase,
                            'cleanup_status',cleanup_status,'cleanup_reason',cleanup_reason,
                            'cancel_requested_at_ms',cancel_requested_at_ms,
                            'outcome_code',outcome_code)
         FROM job_execution WHERE job_id=?1",
        [job],
    ))?;
    sql(tx.execute(
        "DELETE FROM job_events
         WHERE job_id=?1
           AND snapshot_revision <= (SELECT snapshot_revision-?2 FROM job_execution WHERE job_id=?1)",
        rusqlite::params![job, retention.revisions],
    ))?;
    // Keep the longest newest-first suffix that fits the byte bound, and always
    // the newest event, so the retained range stays contiguous.
    sql(tx.execute(
        "DELETE FROM job_events
         WHERE job_id=?1
           AND snapshot_revision < coalesce(
               (SELECT min(snapshot_revision) FROM (
                    SELECT snapshot_revision,
                           sum(length(CAST(snapshot_json AS BLOB)))
                               OVER (ORDER BY snapshot_revision DESC) AS kept
                    FROM job_events WHERE job_id=?1)
                WHERE kept<=?2),
               (SELECT max(snapshot_revision) FROM job_events WHERE job_id=?1))",
        rusqlite::params![job, retention.bytes],
    ))?;
    Ok(())
}

/// Restart reconciliation: only `running` work becomes `interrupted`. Durable
/// user cancellation stays `cancel_requested` with its holds and awaits
/// termination evidence, which `cleanup::record_cleanup` turns into `canceled`
/// (WE-005, ENG-031; ENG-004 "unless durable user cancellation already won").
pub(super) fn interrupt_active(tx: &Transaction<'_>) -> Result<(), CoreError> {
    let mut statement = sql(tx.prepare(
        "SELECT job_id FROM job_execution
         WHERE state='running' ORDER BY job_id LIMIT 129",
    ))?;
    let jobs = sql(statement.query_map([], |r| r.get::<_, String>(0)))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| CoreError::StoreUnavailable)?;
    if jobs.len() > 128 {
        return Err(CoreError::InvalidStore);
    }
    for job in jobs {
        sql(tx.execute(
            "UPDATE job_execution
             SET state='interrupted',phase='interrupted',snapshot_revision=snapshot_revision+1,
                 outcome_code='engine_restarted',updated_at_ms=?2
             WHERE job_id=?1",
            rusqlite::params![job, now_ms()?],
        ))?;
        record_event(tx, &job)?;
    }
    // Never release holds at restart. Recovery reports established cleanup
    // through `cleanup::record_cleanup`, the only writer of those facts.
    Ok(())
}

pub(super) fn cancel(
    db: &mut Connection,
    auth: &AuthContext,
    job: &JobId,
) -> Result<&'static str, CoreError> {
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
    require_active_grant(&tx, auth, "jobs.cancel")?;
    let state: Option<String> = sql(tx
        .query_row(
            "SELECT e.state FROM job_execution e JOIN jobs j USING(job_id)
             WHERE j.job_id=?1 AND j.client_id=?2",
            rusqlite::params![job.as_str(), auth.client_id.as_str()],
            |r| r.get(0),
        )
        .optional())?;
    let state = state.ok_or(CoreError::NotFound)?;
    let effect = match state.as_str() {
        "queued" => "canceled_before_dispatch",
        "running" | "cancel_requested" => "requested",
        _ => "already_terminal",
    };
    if state == "queued" || state == "running" {
        let next = if state == "queued" {
            "canceled"
        } else {
            "cancel_requested"
        };
        let now = now_ms()?;
        sql(tx.execute(
            "UPDATE job_execution
             SET state=?2,phase=?2,cancel_requested_at_ms=?3,snapshot_revision=snapshot_revision+1,
                 updated_at_ms=?3
             WHERE job_id=?1",
            rusqlite::params![job.as_str(), next, now],
        ))?;
        record_event(&tx, job.as_str())?;
    }
    sql(tx.commit())?;
    Ok(effect)
}
