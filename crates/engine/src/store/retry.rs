//! WE-003 exact linked retry: bounded caller preparation and actor-only acceptance.
//!
//! Order matches submission. A retained retry binding is decided first (same
//! source replays, another source conflicts) and never allocates a sequence,
//! observes free space or consults readiness. Fresh work then checks the source
//! (creator, terminal state, cleanup), its retained prerequisites and capacity.
//! The new job copies the source's stored resolution, policy and input
//! references byte for byte in SQL; nothing is re-resolved or remapped.

use super::admission::{
    AcceptancePolicy, AdmissionEpoch, Freshness, Result, check_growth_capacity, commit_fresh,
    input_identity, invalid_store, next_sequence_with_space, read_now, record_acceptance,
};
use super::submission::{ActorTurn, event_bytes, lifecycle_bytes, snapshot_bytes};
use super::*;
use crate::domain::SubmissionError;
use crate::submission::admission::PreparedAdmission;
use dissect3d_api::{
    ErrorCode, ExecutionAcceptance, ExecutionPolicy, JOB_CONTRACT, JobId, ResolvedJob,
};

/// Engine facts a fresh retry needs beyond SQL; replay never consults them.
#[derive(Clone)]
pub(crate) struct RetryPrerequisites {
    /// The currently prepared, verified support resolution, if any.
    pub(crate) prepared: Option<PreparedAdmission>,
    /// Startup input/job reconciliation has finished.
    pub(crate) reconciled: bool,
}

#[derive(Clone, PartialEq, Eq)]
struct RetryBinding {
    source: String,
    job_id: String,
    sequence: i64,
    resolved: String,
}

/// Source facts read under one transaction; the final transaction requires
/// the same facts, so any intervening change makes the preparation stale.
#[derive(Clone, PartialEq, Eq)]
struct Source {
    state: String,
    cleanup: String,
    attempt_cleanup: Option<String>,
    unreleased_reservations: bool,
    storage: String,
    resolved: String,
    timeout_ms: Option<i64>,
    /// Each referenced input's current identity, or `None` if unavailable.
    inputs: Vec<(String, Option<InputIdentity>)>,
}

pub(super) struct RetryRead {
    epoch: AdmissionEpoch,
    binding: Option<RetryBinding>,
    source: Option<Source>,
}

fn retry_binding(
    db: &Connection,
    auth: &AuthContext,
    key: &IdempotencyKey,
) -> Result<Option<RetryBinding>> {
    let binding = sql(db
        .query_row(
            "SELECT b.source_job_id,b.retry_job_id,j.acceptance_sequence,j.resolved_json
             FROM retry_bindings b
             JOIN jobs j ON j.job_id=b.retry_job_id AND j.client_id=b.client_id
             WHERE b.client_id=?1 AND b.idempotency_key=?2",
            rusqlite::params![auth.client_id.as_str(), key.as_str()],
            |r| {
                Ok(RetryBinding {
                    source: r.get(0)?,
                    job_id: r.get(1)?,
                    sequence: r.get(2)?,
                    resolved: r.get(3)?,
                })
            },
        )
        .optional())?;
    Ok(binding)
}

/// Creator-scoped source facts; another client's job reads as absent.
fn source(db: &Connection, auth: &AuthContext, id: &JobId) -> Result<Option<Source>> {
    let row = sql(db
        .query_row(
            "SELECT e.state,e.cleanup_status,a.cleanup_status,
                    EXISTS(SELECT 1 FROM resource_reservations r
                           WHERE r.attempt_id=a.attempt_id AND r.released=0),
                    j.storage_status,j.resolved_json,e.timeout_ms
             FROM jobs j
             JOIN job_execution e USING(job_id)
             LEFT JOIN job_attempts a USING(job_id)
             WHERE j.job_id=?1 AND j.client_id=?2",
            rusqlite::params![id.as_str(), auth.client_id.as_str()],
            |r| {
                Ok(Source {
                    state: r.get(0)?,
                    cleanup: r.get(1)?,
                    attempt_cleanup: r.get(2)?,
                    unreleased_reservations: r.get(3)?,
                    storage: r.get(4)?,
                    resolved: r.get(5)?,
                    timeout_ms: r.get(6)?,
                    inputs: Vec::new(),
                })
            },
        )
        .optional())?;
    let Some(mut source) = row else {
        return Ok(None);
    };
    let now = read_now(db)?;
    let mut statement = sql(
        db.prepare("SELECT input_id FROM job_inputs WHERE job_id=?1 ORDER BY input_id LIMIT 65")
    )?;
    let ids = sql(statement
        .query_map([id.as_str()], |r| r.get::<_, String>(0))
        .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>()))?;
    if ids.is_empty() || ids.len() > 64 {
        return Err(invalid_store());
    }
    for raw in ids {
        let input = InputId::parse(&raw).map_err(|_| invalid_store())?;
        let identity = match input_identity(db, auth, &input, now) {
            Ok(identity) => Some(identity),
            Err(error) if error.code == ErrorCode::InputUnavailable => None,
            Err(error) => return Err(error),
        };
        source.inputs.push((raw, identity));
    }
    Ok(Some(source))
}

pub(super) fn read_retry(
    db: &mut Connection,
    auth: &AuthContext,
    key: &IdempotencyKey,
    source_id: &JobId,
    epoch: AdmissionEpoch,
) -> Result<RetryRead> {
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Deferred))?;
    require_active_grant(&tx, auth, "jobs.retry")?;
    let binding = retry_binding(&tx, auth, key)?;
    // Replay is decided by the binding alone; the source is not consulted.
    let source = match binding {
        Some(_) => None,
        None => source(&tx, auth, source_id)?,
    };
    sql(tx.commit())?;
    Ok(RetryRead {
        epoch,
        binding,
        source,
    })
}

pub(super) struct RetryPrepared {
    state: RetryRead,
    pub(super) observed_at: Instant,
    outcome: Result<Outcome>,
}
enum Outcome {
    Replay(Box<ExecutionAcceptance>),
    Fresh(Box<Fresh>),
}
struct Fresh {
    receipt: ExecutionAcceptance,
    input_ids: Vec<InputIdentity>,
    binding_bytes: usize,
    event_bytes: usize,
    snapshot_bytes: usize,
    response_bytes: usize,
    lifecycle_bytes: usize,
    free: u64,
}

fn acceptance(
    job_id: JobId,
    source: &JobId,
    sequence: i64,
    replayed: bool,
    resolved: ResolvedJob,
) -> Result<ExecutionAcceptance> {
    let receipt = ExecutionAcceptance {
        api_version: "1.0".into(),
        accepted: true,
        job_id,
        replayed,
        acceptance_sequence: sequence,
        snapshot_revision: 1,
        resolved,
        job_contract: JOB_CONTRACT.into(),
        retry_of: Some(source.clone()),
    };
    dissect3d_api::ExecutionRecord::validate(&receipt).map_err(|_| invalid_store())?;
    Ok(receipt)
}

fn decode_resolved(bytes: &str) -> Result<ResolvedJob> {
    dissect3d_api::decode_submission_json(bytes.as_bytes(), 262_144).map_err(|_| invalid_store())
}

pub(super) fn prepare_retry(
    root: &OwnedRoot,
    auth: &AuthContext,
    key: &IdempotencyKey,
    source_id: &JobId,
    prerequisites: &RetryPrerequisites,
    state: RetryRead,
) -> RetryPrepared {
    let mut observed_at = Instant::now();
    let outcome = match (&state.binding, &state.source) {
        (Some(binding), _) => replay(binding, source_id),
        (None, None) => Err(ErrorCode::NotFound.into()),
        (None, Some(source)) => fresh(
            root,
            auth,
            key,
            source_id,
            source,
            prerequisites,
            &mut observed_at,
        ),
    };
    RetryPrepared {
        state,
        observed_at,
        outcome,
    }
}

/// Same key: the same source replays the original receipt; another conflicts.
fn replay(binding: &RetryBinding, source_id: &JobId) -> Result<Outcome> {
    if binding.source != source_id.as_str() {
        return Err(ErrorCode::IdempotencyConflict.into());
    }
    let job_id = JobId::parse(&binding.job_id).map_err(|_| invalid_store())?;
    let receipt = acceptance(
        job_id,
        source_id,
        binding.sequence,
        true,
        decode_resolved(&binding.resolved)?,
    )?;
    Ok(Outcome::Replay(Box::new(receipt)))
}

/// Source and prerequisite checks, budgets and the free-space observation.
fn fresh(
    root: &OwnedRoot,
    auth: &AuthContext,
    key: &IdempotencyKey,
    source_id: &JobId,
    source: &Source,
    prerequisites: &RetryPrerequisites,
    observed_at: &mut Instant,
) -> Result<Outcome> {
    if !prerequisites.reconciled {
        return Err(ErrorCode::EngineRecovering.into());
    }
    // Every terminal outcome may be retried explicitly; WE-003 requires only a
    // terminal source. A retry is always a new job; the source never changes.
    if !matches!(
        source.state.as_str(),
        "succeeded" | "partial" | "failed" | "canceled" | "interrupted"
    ) {
        return Err(ErrorCode::JobNotTerminal.into());
    }
    let unresolved = |status: &str| matches!(status, "pending" | "fault");
    if unresolved(&source.cleanup)
        || source.attempt_cleanup.as_deref().is_some_and(unresolved)
        || source.unreleased_reservations
    {
        return Err(ErrorCode::CleanupUnconfirmed.into());
    }
    let unavailable = || SubmissionError::from(ErrorCode::RetryPrerequisiteUnavailable);
    if source.storage != "verified" {
        return Err(unavailable());
    }
    let resolved = decode_resolved(&source.resolved)?;
    // Inputs must still be complete with the exact identities the source captured.
    let mut retained: Vec<_> = resolved.inputs.values().flatten().cloned().collect();
    retained.sort_by(|a, b| a.input_id.as_str().cmp(b.input_id.as_str()));
    retained.dedup();
    let current = source
        .inputs
        .iter()
        .map(|(_, identity)| identity.clone().ok_or_else(unavailable))
        .collect::<Result<Vec<_>>>()?;
    if current != retained {
        return Err(unavailable());
    }
    // The exact retained resolution must be the one currently prepared.
    if !prerequisites
        .prepared
        .as_ref()
        .is_some_and(|prepared| prepared.covers(&resolved))
    {
        return Err(unavailable());
    }
    // The actor assigns the sequence; budgets use the maximum width.
    let sequence = i64::MAX;
    let job_id = JobId::parse(random_id("job_")?).map_err(|_| invalid_store())?;
    let binding_bytes = serde_json::to_vec(&serde_json::json!({
        "client_id": auth.client_id,
        "operation": "jobs.retry",
        "key": key,
        "source_job_id": source_id,
        "retry_job_id": job_id,
    }))
    .map_err(|_| invalid_store())?
    .len();
    let event_bytes = event_bytes(&job_id, sequence)?;
    let snapshot_bytes = snapshot_bytes(&job_id, sequence, &resolved)?;
    let policy = ExecutionPolicy {
        timeout_ms: source
            .timeout_ms
            .map(u64::try_from)
            .transpose()
            .map_err(|_| invalid_store())?,
    };
    let lifecycle_bytes = lifecycle_bytes(&Some(&policy))?;
    let receipt = acceptance(job_id, source_id, sequence, false, resolved)?;
    let response_bytes = serde_json::to_vec(&receipt)
        .map_err(|_| invalid_store())?
        .len();
    *observed_at = Instant::now();
    let free = root
        .available_space_bytes()
        .map_err(|_| SubmissionError::from(ErrorCode::StorageUnavailable))?;
    Ok(Outcome::Fresh(Box::new(Fresh {
        receipt,
        input_ids: current,
        binding_bytes,
        event_bytes,
        snapshot_bytes,
        response_bytes,
        lifecycle_bytes,
        free,
    })))
}

/// One final retry transaction, as handed to the actor.
pub(super) struct RetryFinish {
    pub(super) auth: AuthContext,
    pub(super) key: IdempotencyKey,
    pub(super) source: JobId,
    pub(super) prepared: RetryPrepared,
}

/// `None` means a stale preparation, not a rejection or an accepted outcome.
pub(super) fn finish_retry(
    connection: &mut Connection,
    turn: ActorTurn<'_>,
    request: RetryFinish,
) -> Result<Option<ExecutionAcceptance>> {
    let RetryFinish {
        auth,
        key,
        source: source_id,
        prepared,
    } = request;
    let transaction = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
    require_active_grant(&transaction, &auth, "jobs.retry")?;
    if retry_binding(&transaction, &auth, &key)? != prepared.state.binding {
        return Ok(None);
    }
    let freshness = Freshness {
        root: turn.root,
        read: prepared.state.epoch,
        current: turn.epoch,
        observed_at: prepared.observed_at,
    };
    let is_fresh = prepared.state.binding.is_none();
    if is_fresh && freshness.stale_at_entry() {
        return Ok(None);
    }
    // Source facts are rechecked here even when preparation rejected, so a
    // rejection reflects the source as it is now, not an older read.
    if is_fresh && source(&transaction, &auth, &source_id)? != prepared.state.source {
        return Ok(None);
    }
    let fresh = match prepared.outcome? {
        Outcome::Replay(receipt) => {
            // Replay writes nothing: no sequence, clock or capacity decision.
            sql(transaction.commit())?;
            return Ok(Some(*receipt));
        }
        Outcome::Fresh(fresh) => *fresh,
    };
    let AcceptancePolicy {
        stopping,
        fail_commit,
        response_limit,
        limits,
    } = turn.policy;
    if stopping {
        return Err(ErrorCode::EngineStopping.into());
    }
    let reserved = check_growth_capacity(&transaction, &limits, fresh.input_ids.iter())?;
    let Some(sequence) =
        next_sequence_with_space(&transaction, &freshness, fresh.free, reserved, &limits)?
    else {
        return Ok(None);
    };
    if fresh.binding_bytes > 16_384 {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
    if fresh.response_bytes > response_limit.min(262_144)
        || fresh.snapshot_bytes > response_limit.min(262_144)
    {
        return Err(ErrorCode::CapacityExceeded.into());
    }
    if fresh.snapshot_bytes + fresh.binding_bytes + fresh.event_bytes + fresh.lifecycle_bytes
        > limits.metadata_bytes
    {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
    let mut receipt = fresh.receipt;
    receipt.acceptance_sequence = sequence;
    let (job, source_job) = (receipt.job_id.as_str(), source_id.as_str());
    let now = read_now(&transaction)?;
    // Copy the stored resolution, policy and input references exactly.
    let copied = sql(transaction.execute(
        "INSERT INTO jobs(job_id,client_id,acceptance_sequence,created_at_ms,resolved_json,storage_status)
         SELECT ?1,client_id,?2,?3,resolved_json,'verified' FROM jobs
         WHERE job_id=?4 AND client_id=?5",
        rusqlite::params![job, sequence, now, source_job, auth.client_id.as_str()],
    ))?;
    if copied != 1 {
        return Err(invalid_store());
    }
    sql(transaction.execute(
        "INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms,
                                   timeout_ms,retry_of)
         SELECT ?1,1,'queued','queued','confirmed',?2,timeout_ms,job_id FROM job_execution
         WHERE job_id=?3",
        rusqlite::params![job, now, source_job],
    ))?;
    sql(transaction.execute(
        "INSERT INTO retry_bindings(client_id,idempotency_key,source_job_id,retry_job_id)
         VALUES(?1,?2,?3,?4)",
        rusqlite::params![auth.client_id.as_str(), key.as_str(), source_job, job],
    ))?;
    let inputs = sql(transaction.execute(
        "INSERT INTO job_inputs(job_id,input_id) SELECT ?1,input_id FROM job_inputs WHERE job_id=?2",
        rusqlite::params![job, source_job],
    ))?;
    if inputs != fresh.input_ids.len() {
        return Err(invalid_store());
    }
    record_acceptance(&transaction, job, sequence)?;
    Ok(commit_fresh(transaction, &freshness, fail_commit)?.map(|()| receipt))
}
