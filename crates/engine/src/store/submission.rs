//! Bounded caller preparation and actor-only atomic queued acceptance.

use super::admission::{
    AcceptancePolicy, AdmissionEpoch, Freshness, Result, check_growth_capacity, commit_fresh,
    input_identity, invalid_store, next_sequence_with_space, read_now, record_acceptance,
};
use super::inputs::observe_wall_time_at;
use super::*;
use crate::domain::SubmissionError;
use crate::submission::admission::AdmissionCandidate;
use crate::submission::equivalence::{SubmittedJobRequest, VerifiedInputMap};
use dissect3d_api::{AcceptanceReceipt, ErrorCode, JobId, ResolvedJob};

// Preparation is synchronous on an already-blocking caller, never the SQL actor.
// Two permits bound retained snapshots and work, including abandoned async callers.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Binding {
    version: i64,
    fingerprint: Vec<u8>,
    originals: String,
    job_id: String,
    sequence: i64,
    resolved: String,
}
pub(super) struct ReadState {
    epoch: AdmissionEpoch,
    binding: Option<Binding>,
    identities: VerifiedInputMap,
}
fn binding(db: &Connection, auth: &AuthContext, key: &IdempotencyKey) -> Result<Option<Binding>> {
    let binding = sql(db
        .query_row(
            "SELECT b.canonicalization_version,b.fingerprint,b.original_inputs_json,b.job_id,
                    j.acceptance_sequence,j.resolved_json
             FROM submission_bindings b
             JOIN jobs j ON j.job_id=b.job_id AND j.client_id=b.client_id
             WHERE b.client_id=?1 AND b.operation='jobs.submit' AND b.idempotency_key=?2",
            rusqlite::params![auth.client_id.as_str(), key.as_str()],
            |r| {
                Ok(Binding {
                    version: r.get(0)?,
                    fingerprint: r.get(1)?,
                    originals: r.get(2)?,
                    job_id: r.get(3)?,
                    sequence: r.get(4)?,
                    resolved: r.get(5)?,
                })
            },
        )
        .optional())?;
    Ok(binding)
}
pub(super) fn read_state(
    db: &mut Connection,
    auth: &AuthContext,
    key: &IdempotencyKey,
    submitted: &SubmittedJobRequest,
    epoch: AdmissionEpoch,
) -> Result<ReadState> {
    // A read-only snapshot: the authoritative clock write and expiry recheck
    // happen in `finish`. Reading max(now, last observed) keeps expiry monotonic.
    let tx = sql(db.transaction_with_behavior(TransactionBehavior::Deferred))?;
    require_active_grant(&tx, auth, "jobs.submit")?;
    let binding = binding(&tx, auth, key)?;
    let now = read_now(&tx)?;
    let mut identities = VerifiedInputMap::new();
    for input in submitted.base().inputs.values().flatten() {
        if !identities.contains_key(input.input_id.as_str()) {
            match input_identity(&tx, auth, &input.input_id, now) {
                Ok(identity) => {
                    identities.insert(input.input_id.as_str().to_owned(), identity);
                }
                Err(e) if e.code == ErrorCode::InputUnavailable => {}
                Err(e) => return Err(e),
            }
        }
    }
    sql(tx.commit())?;
    Ok(ReadState {
        epoch,
        binding,
        identities,
    })
}
pub(super) struct Prepared {
    state: ReadState,
    pub(super) observed_at: Instant,
    outcome: Result<Outcome>,
}
enum Outcome {
    /// A replay receipt (or none), plus replacement-input identities to recheck.
    Probe(Option<Box<AcceptanceReceipt>>, VerifiedInputMap),
    Fresh(Box<Fresh>),
}
struct Fresh {
    receipt: AcceptanceReceipt,
    resolved: String,
    originals: String,
    binding_bytes: usize,
    event_bytes: usize,
    snapshot_bytes: usize,
    response_bytes: usize,
    lifecycle_bytes: usize,
    free: u64,
}

pub(super) fn prepare(
    root: &OwnedRoot,
    auth: &AuthContext,
    key: &IdempotencyKey,
    submitted: &SubmittedJobRequest,
    candidate: Option<&AdmissionCandidate>,
    state: ReadState,
) -> Prepared {
    let mut observed_at = Instant::now();
    let outcome = match (&state.binding, candidate) {
        (Some(binding), _) => replay_outcome(binding, submitted, &state.identities),
        (None, None) => Ok(Outcome::Probe(None, VerifiedInputMap::new())),
        (None, Some(candidate)) => {
            fresh_outcome(root, auth, key, submitted, candidate, &mut observed_at)
        }
    };
    Prepared {
        state,
        observed_at,
        outcome,
    }
}

/// Compare a retained binding with this request; never allocates fresh facts.
fn replay_outcome(
    binding: &Binding,
    submitted: &SubmittedJobRequest,
    identities: &VerifiedInputMap,
) -> Result<Outcome> {
    if binding.version != submitted.version() {
        return Err(if submitted.version() == 1 {
            ErrorCode::IncompatibleContract
        } else {
            ErrorCode::IdempotencyConflict
        }
        .into());
    }
    let originals: VerifiedInputMap =
        dissect3d_api::decode_submission_json(binding.originals.as_bytes(), 16_384)
            .map_err(|_| invalid_store())?;
    let mut verified = VerifiedInputMap::new();
    let mut current = VerifiedInputMap::new();
    for input in submitted.base().inputs.values().flatten() {
        let id = input.input_id.as_str();
        let identity = if let Some(identity) = originals.get(id) {
            identity.clone()
        } else {
            let identity = identities
                .get(id)
                .ok_or_else(|| SubmissionError::from(ErrorCode::InputUnavailable))?
                .clone();
            current.insert(id.to_owned(), identity.clone());
            identity
        };
        verified.insert(id.to_owned(), identity);
    }
    let canonical = submitted
        .canonicalize(&verified)
        .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
    if canonical.fingerprint.as_slice() != binding.fingerprint {
        return Err(ErrorCode::IdempotencyConflict.into());
    }
    let resolved: ResolvedJob =
        dissect3d_api::decode_submission_json(binding.resolved.as_bytes(), 262_144)
            .map_err(|_| invalid_store())?;
    let receipt = AcceptanceReceipt {
        api_version: "1.0".into(),
        accepted: true,
        job_id: JobId::parse(&binding.job_id).map_err(|_| invalid_store())?,
        replayed: true,
        acceptance_sequence: binding.sequence,
        snapshot_revision: 1,
        resolved,
    };
    receipt.validate().map_err(|_| invalid_store())?;
    Ok(Outcome::Probe(Some(Box::new(receipt)), current))
}

/// Caller-side budgets and the free-space observation for a fresh acceptance.
fn fresh_outcome(
    root: &OwnedRoot,
    auth: &AuthContext,
    key: &IdempotencyKey,
    submitted: &SubmittedJobRequest,
    candidate: &AdmissionCandidate,
    observed_at: &mut Instant,
) -> Result<Outcome> {
    if submitted
        .canonicalize(&candidate.original_inputs)
        .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?
        != candidate.canonical
    {
        return Err(ErrorCode::InvalidRequest.into());
    }
    // The actor assigns the sequence at finish. Size every budget with the
    // maximum-width value, as for the timestamp below.
    let sequence = i64::MAX;
    let job_id = JobId::parse(random_id("job_")?).map_err(|_| invalid_store())?;
    let receipt = AcceptanceReceipt {
        api_version: "1.0".into(),
        accepted: true,
        job_id: job_id.clone(),
        replayed: false,
        acceptance_sequence: sequence,
        snapshot_revision: 1,
        resolved: candidate.resolved.clone(),
    };
    receipt.validate().map_err(|_| invalid_store())?;
    let resolved = serde_json::to_string(&candidate.resolved).map_err(|_| invalid_store())?;
    let originals =
        serde_json::to_string(&candidate.original_inputs).map_err(|_| invalid_store())?;
    let binding_bytes = serde_json::to_vec(&serde_json::json!({
        "client_id": auth.client_id,
        "operation": "jobs.submit",
        "key": key,
        "job_id": job_id,
        "canonicalization_version": submitted.version(),
        "fingerprint": digest_hex(&candidate.canonical.fingerprint),
        "original_inputs": candidate.original_inputs,
    }))
    .map_err(|_| invalid_store())?
    .len();
    let event_bytes = event_bytes(&job_id, sequence)?;
    // The final timestamp is not known yet. Use the maximum valid wire width
    // for the response budget, while the transaction records its fresh time.
    let snapshot_bytes = snapshot_bytes(&job_id, sequence, &candidate.resolved)?;
    let response_bytes = serde_json::to_vec(&receipt)
        .map_err(|_| invalid_store())?
        .len();
    let lifecycle_bytes = if submitted.version() == 2 {
        lifecycle_bytes(&submitted.execution())?
    } else {
        0
    };
    *observed_at = Instant::now();
    let free = root
        .available_space_bytes()
        .map_err(|_| SubmissionError::from(ErrorCode::StorageUnavailable))?;
    Ok(Outcome::Fresh(Box::new(Fresh {
        receipt,
        resolved,
        originals,
        binding_bytes,
        event_bytes,
        snapshot_bytes,
        response_bytes,
        lifecycle_bytes,
        free,
    })))
}

/// Encoded acceptance event size for metadata budgets.
pub(super) fn event_bytes(job_id: &JobId, sequence: i64) -> Result<usize> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "job_id": job_id,
        "acceptance_sequence": sequence,
        "snapshot_revision": 1,
    }))
    .map_err(|_| invalid_store())?
    .len())
}

/// Encoded queued snapshot size at the maximum timestamp width.
pub(super) fn snapshot_bytes(
    job_id: &JobId,
    sequence: i64,
    resolved: &ResolvedJob,
) -> Result<usize> {
    let snapshot = dissect3d_api::JobSnapshot {
        api_version: "1.0".into(),
        summary: super::jobs::summary(job_id.as_str().to_owned(), sequence, i64::MAX)?,
        resolved: resolved.clone(),
        storage_status: dissect3d_api::StorageStatus::Verified,
        attempt_id: None,
        result_id: None,
    };
    Ok(serde_json::to_vec(&snapshot)
        .map_err(|_| invalid_store())?
        .len())
}

/// Lifecycle allowance for an execution-aware job and its policy.
pub(super) fn lifecycle_bytes(policy: &impl serde::Serialize) -> Result<usize> {
    Ok(2048
        + serde_json::to_vec(policy)
            .map_err(|_| invalid_store())?
            .len())
}

/// One final submission transaction, as handed to the actor.
pub(super) struct Finish<'a> {
    pub(super) auth: AuthContext,
    pub(super) key: IdempotencyKey,
    pub(super) submitted: SubmittedJobRequest,
    pub(super) candidate: Option<&'a AdmissionCandidate>,
    pub(super) prepared: Prepared,
}

/// Actor state the final transaction is judged against.
pub(super) struct ActorTurn<'a> {
    pub(super) root: &'a OwnedRoot,
    pub(super) epoch: AdmissionEpoch,
    pub(super) policy: AcceptancePolicy,
}

/// None means a stale preparation, not a rejection or an accepted outcome.
pub(super) fn finish(
    connection: &mut Connection,
    turn: ActorTurn<'_>,
    request: Finish<'_>,
) -> Result<Option<Option<AcceptanceReceipt>>> {
    let Finish {
        auth: context,
        key,
        submitted,
        candidate,
        prepared,
    } = request;
    let transaction = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
    require_active_grant(&transaction, &context, "jobs.submit")?;
    if binding(&transaction, &context, &key)? != prepared.state.binding {
        return Ok(None);
    }
    let freshness = Freshness {
        root: turn.root,
        read: prepared.state.epoch,
        current: turn.epoch,
        observed_at: prepared.observed_at,
    };
    if prepared.state.binding.is_none() && candidate.is_some() && freshness.stale_at_entry() {
        return Ok(None);
    }
    let prepared = match prepared.outcome? {
        Outcome::Probe(receipt, current) => {
            // Nothing to recheck means no clock write and no write commit.
            if !current.is_empty() {
                let now = observe_wall_time_at(&transaction, now_ms()?)?;
                for identity in current.values() {
                    if input_identity(&transaction, &context, &identity.input_id, now)? != *identity
                    {
                        return Err(ErrorCode::InputUnavailable.into());
                    }
                }
            }
            sql(transaction.commit())?;
            return Ok(Some(receipt.map(|r| *r)));
        }
        Outcome::Fresh(prepared) => *prepared,
    };
    let candidate = candidate.ok_or_else(invalid_store)?;
    let AcceptancePolicy {
        stopping,
        fail_commit,
        response_limit,
        limits,
    } = turn.policy;
    if stopping {
        return Err(ErrorCode::EngineStopping.into());
    }
    if candidate.request_bytes > 65_536
        || candidate.binding_bytes > 16_384
        || candidate.metadata_bytes > limits.metadata_bytes
        || candidate.response_bytes > response_limit.min(262_144)
    {
        return Err(ErrorCode::CapacityExceeded.into());
    }
    if candidate.obj_summaries.len() != candidate.original_inputs.len() {
        return Err(ErrorCode::InvalidInput.into());
    }
    let now = observe_wall_time_at(&transaction, now_ms()?)?;
    for identity in candidate.original_inputs.values() {
        if input_identity(&transaction, &context, &identity.input_id, now)? != *identity {
            return Err(ErrorCode::InputUnavailable.into());
        }
    }
    let reserved =
        check_growth_capacity(&transaction, &limits, candidate.original_inputs.values())?;
    let Some(sequence) =
        next_sequence_with_space(&transaction, &freshness, prepared.free, reserved, &limits)?
    else {
        return Ok(None);
    };
    if prepared.binding_bytes > 16_384 {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
    if prepared.response_bytes > response_limit.min(262_144)
        || prepared.snapshot_bytes > response_limit.min(262_144)
    {
        return Err(ErrorCode::CapacityExceeded.into());
    }
    if prepared.snapshot_bytes
        + prepared.binding_bytes
        + prepared.event_bytes
        + prepared.lifecycle_bytes
        > limits.metadata_bytes
    {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
    let mut receipt = prepared.receipt;
    receipt.acceptance_sequence = sequence;
    let job_id = receipt.job_id.as_str();
    sql(transaction.execute(
        "INSERT INTO jobs VALUES(?1,?2,?3,?4,?5,'verified')",
        rusqlite::params![
            job_id,
            context.client_id.as_str(),
            sequence,
            now,
            prepared.resolved
        ],
    ))?;
    sql(transaction.execute(
        "INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms,timeout_ms)
         VALUES(?1,1,'queued','queued','confirmed',?2,?3)",
        rusqlite::params![
            job_id,
            now,
            submitted
                .execution()
                .and_then(|p| p.timeout_ms)
                .map(|ms| ms as i64)
        ],
    ))?;
    sql(transaction.execute(
        "INSERT INTO submission_bindings VALUES(?1,'jobs.submit',?2,?3,?6,?4,?5)",
        rusqlite::params![
            context.client_id.as_str(),
            key.as_str(),
            job_id,
            candidate.canonical.fingerprint.as_slice(),
            prepared.originals,
            submitted.version()
        ],
    ))?;
    for identity in candidate.original_inputs.values() {
        sql(transaction.execute(
            "INSERT INTO job_inputs VALUES(?1,?2)",
            rusqlite::params![job_id, identity.input_id.as_str()],
        ))?;
    }
    record_acceptance(&transaction, job_id, sequence)?;
    Ok(commit_fresh(transaction, &freshness, fail_commit)?.map(|()| Some(receipt)))
}
