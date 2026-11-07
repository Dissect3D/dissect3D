//! Atomic queued acceptance. Only the metadata actor calls these functions.

use super::inputs::observe_wall_time_at;
use super::*;
use crate::submission::SubmissionError;
use crate::submission::admission::AdmissionCandidate;
use crate::submission::equivalence::{VerifiedInputMap, canonicalize};
use dissect3d_api::{AcceptanceReceipt, ErrorCode, JobId, JobRequest, ResolvedJob};

type Result<T> = std::result::Result<T, SubmissionError>;
type StoredBinding = (i64, Vec<u8>, String, String);

fn invalid_store() -> SubmissionError {
    ErrorCode::StoreUnavailable.into()
}
fn sql<T>(value: rusqlite::Result<T>) -> Result<T> {
    value.map_err(|_| invalid_store())
}

pub(super) fn input_identity(
    connection: &Connection,
    context: &AuthContext,
    id: &InputId,
    now: i64,
) -> Result<InputIdentity> {
    let row: Option<(String, i64, Vec<u8>)> = sql(connection.query_row(
        "SELECT media_type,byte_length,sha256 FROM captured_inputs
         WHERE input_id=?1 AND client_id=?2 AND cleanup_state='complete' AND (expires_at_ms>?3 OR EXISTS(SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id))",
        rusqlite::params![id.as_str(), context.client_id.as_str(), now],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional())?;
    let (media_type, length, digest) =
        row.ok_or_else(|| SubmissionError::from(ErrorCode::InputUnavailable))?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| invalid_store())?;
    Ok(InputIdentity {
        input_id: id.clone(),
        media_type,
        byte_length: u64::try_from(length).map_err(|_| invalid_store())?,
        sha256: ContentDigest::parse(digest_hex(&digest)).map_err(|_| invalid_store())?,
    })
}

pub(super) fn probe(
    connection: &Transaction<'_>,
    context: &AuthContext,
    key: &IdempotencyKey,
    request: &JobRequest,
) -> Result<Option<AcceptanceReceipt>> {
    require_active_grant(connection, context, "jobs.submit")?;
    let binding: Option<StoredBinding> = sql(connection.query_row(
        "SELECT canonicalization_version,fingerprint,original_inputs_json,job_id
         FROM submission_bindings WHERE client_id=?1 AND operation='jobs.submit' AND idempotency_key=?2",
        rusqlite::params![context.client_id.as_str(), key.as_str()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).optional())?;
    let Some((version, fingerprint, originals, job_id)) = binding else {
        return Ok(None);
    };
    if version != 1 {
        return Err(ErrorCode::IncompatibleContract.into());
    }
    let originals: VerifiedInputMap =
        dissect3d_api::decode_submission_json(originals.as_bytes(), 16_384)
            .map_err(|_| invalid_store())?;
    let now = observe_wall_time_at(connection, now_ms()?)?;
    let mut verified = VerifiedInputMap::new();
    for input in request.inputs.values().flatten() {
        if !verified.contains_key(input.input_id.as_str()) {
            let identity = match originals.get(input.input_id.as_str()) {
                Some(identity) => identity.clone(),
                None => input_identity(connection, context, &input.input_id, now)?,
            };
            verified.insert(input.input_id.as_str().to_owned(), identity);
        }
    }
    let canonical = canonicalize(request, &verified)
        .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
    if canonical.fingerprint.as_slice() != fingerprint {
        return Err(ErrorCode::IdempotencyConflict.into());
    }
    let (sequence, resolved): (i64, String) = sql(connection.query_row(
        "SELECT acceptance_sequence,resolved_json FROM jobs WHERE job_id=?1 AND client_id=?2",
        rusqlite::params![job_id, context.client_id.as_str()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))?;
    let resolved: ResolvedJob = dissect3d_api::decode_submission_json(resolved.as_bytes(), 262_144)
        .map_err(|_| invalid_store())?;
    let receipt = AcceptanceReceipt {
        api_version: "1.0".into(),
        accepted: true,
        job_id: JobId::parse(job_id).map_err(|_| invalid_store())?,
        replayed: true,
        acceptance_sequence: sequence,
        snapshot_revision: 1,
        resolved,
    };
    receipt.validate().map_err(|_| invalid_store())?;
    Ok(Some(receipt))
}

/// Fixed product bounds. Tests may lower them only inside their private actor.
#[derive(Clone, Copy)]
pub(crate) struct AcceptanceLimits {
    pub(crate) queued: i64,
    pub(crate) bindings: i64,
    pub(crate) captured_bytes: u64,
    pub(crate) metadata_bytes: usize,
    pub(crate) free_reserve: u64,
}

impl Default for AcceptanceLimits {
    fn default() -> Self {
        Self {
            queued: 128,
            bindings: 65_536,
            captured_bytes: 17_179_869_184,
            metadata_bytes: 262_144,
            free_reserve: STORAGE_FREE_RESERVE_BYTES,
        }
    }
}

pub(super) struct AcceptancePolicy {
    pub(super) stopping: bool,
    pub(super) fail_commit: bool,
    pub(super) response_limit: usize,
    pub(super) limits: AcceptanceLimits,
}

pub(super) fn accept(
    connection: &mut Connection,
    root: &OwnedRoot,
    context: AuthContext,
    key: IdempotencyKey,
    request: JobRequest,
    candidate: AdmissionCandidate,
    policy: AcceptancePolicy,
) -> Result<AcceptanceReceipt> {
    let AcceptancePolicy {
        stopping,
        fail_commit,
        response_limit,
        limits,
    } = policy;
    let transaction = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
    if let Some(receipt) = probe(&transaction, &context, &key, &request)? {
        sql(transaction.commit())?;
        return Ok(receipt);
    }
    if stopping {
        return Err(ErrorCode::EngineStopping.into());
    }
    if canonicalize(&request, &candidate.original_inputs)
        .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?
        != candidate.canonical
    {
        return Err(ErrorCode::InvalidRequest.into());
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
    let queued: i64 =
        sql(transaction.query_row("SELECT count(*) FROM jobs", [], |row| row.get(0)))?;
    let bindings: i64 = sql(transaction.query_row(
        "SELECT count(*) FROM submission_bindings",
        [],
        |row| row.get(0),
    ))?;
    if queued >= limits.queued {
        return Err(CoreError::CapacityExceeded("queued_jobs_max").into());
    }
    if bindings >= limits.bindings {
        return Err(CoreError::CapacityExceeded("submission_bindings_max").into());
    }
    let captured: i64 = sql(transaction.query_row(
        "SELECT coalesce(sum(byte_length),0) FROM captured_inputs WHERE EXISTS
         (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
        [],
        |row| row.get(0),
    ))?;
    let mut additional = 0u64;
    for identity in candidate.original_inputs.values() {
        let referenced: bool = sql(transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM job_inputs WHERE input_id=?1)",
            [identity.input_id.as_str()],
            |row| row.get(0),
        ))?;
        if !referenced {
            additional = additional
                .checked_add(identity.byte_length)
                .ok_or_else(invalid_store)?;
        }
    }
    if (captured as u64)
        .checked_add(additional)
        .is_none_or(|bytes| bytes > limits.captured_bytes)
    {
        return Err(CoreError::CapacityExceeded("captured_input_bytes_max").into());
    }
    let reserved: i64 = sql(transaction.query_row(
        "SELECT coalesce(sum(declared_length),0)+count(*)*4194304 FROM input_upload_reservations",
        [],
        |row| row.get(0),
    ))?;
    let growth = 4_194_304u64;
    let free = root
        .available_space_bytes()
        .map_err(|_| SubmissionError::from(ErrorCode::StorageUnavailable))?;
    if free
        < (reserved as u64)
            .saturating_add(growth)
            .saturating_add(limits.free_reserve)
    {
        return Err(CoreError::CapacityExceeded("storage_free_reserve_bytes").into());
    }
    let old: i64 = sql(transaction.query_row(
        "SELECT value FROM job_sequence WHERE singleton=1",
        [],
        |row| row.get(0),
    ))?;
    let sequence = old
        .checked_add(1)
        .ok_or_else(|| SubmissionError::from(ErrorCode::CapacityExceeded))?;
    let job_id = JobId::parse(random_id("job_")?).map_err(|_| invalid_store())?;
    let resolved = serde_json::to_string(&candidate.resolved).map_err(|_| invalid_store())?;
    let originals =
        serde_json::to_string(&candidate.original_inputs).map_err(|_| invalid_store())?;
    let binding_bytes = serde_json::to_vec(&serde_json::json!({
        "client_id":context.client_id,"operation":"jobs.submit","key":key,"job_id":job_id,
        "canonicalization_version":1,"fingerprint":digest_hex(&candidate.canonical.fingerprint),
        "original_inputs": candidate.original_inputs,
    }))
    .map_err(|_| invalid_store())?
    .len();
    let event_bytes = serde_json::to_vec(
        &serde_json::json!({"job_id":job_id,"acceptance_sequence":sequence,"snapshot_revision":1}),
    )
    .map_err(|_| invalid_store())?
    .len();
    if binding_bytes > 16_384 {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
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
    if serde_json::to_vec(&receipt)
        .map_err(|_| invalid_store())?
        .len()
        > response_limit.min(262_144)
    {
        return Err(ErrorCode::CapacityExceeded.into());
    }
    let snapshot = dissect3d_api::JobSnapshot {
        api_version: "1.0".into(),
        summary: super::jobs::summary(job_id.as_str().to_owned(), sequence, now)?,
        resolved: candidate.resolved.clone(),
        storage_status: dissect3d_api::StorageStatus::Verified,
        attempt_id: None,
        result_id: None,
    };
    if serde_json::to_vec(&snapshot)
        .map_err(|_| invalid_store())?
        .len()
        > response_limit.min(262_144)
    {
        return Err(ErrorCode::CapacityExceeded.into());
    }
    let snapshot_bytes = serde_json::to_vec(&snapshot)
        .map_err(|_| invalid_store())?
        .len();
    if snapshot_bytes + binding_bytes + event_bytes > limits.metadata_bytes {
        return Err(CoreError::CapacityExceeded("job_metadata_bytes_max").into());
    }
    sql(transaction.execute(
        "UPDATE job_sequence SET value=?1 WHERE singleton=1",
        [sequence],
    ))?;
    sql(transaction.execute(
        "INSERT INTO jobs VALUES(?1,?2,?3,?4,?5,'verified')",
        rusqlite::params![
            job_id.as_str(),
            context.client_id.as_str(),
            sequence,
            now,
            resolved
        ],
    ))?;
    sql(transaction.execute(
        "INSERT INTO submission_bindings VALUES(?1,'jobs.submit',?2,?3,1,?4,?5)",
        rusqlite::params![
            context.client_id.as_str(),
            key.as_str(),
            job_id.as_str(),
            candidate.canonical.fingerprint.as_slice(),
            originals
        ],
    ))?;
    for identity in candidate.original_inputs.values() {
        sql(transaction.execute(
            "INSERT INTO job_inputs VALUES(?1,?2)",
            rusqlite::params![job_id.as_str(), identity.input_id.as_str()],
        ))?;
    }
    sql(transaction.execute(
        "INSERT INTO job_acceptance_events VALUES(?1,?2,1)",
        rusqlite::params![job_id.as_str(), sequence],
    ))?;
    #[cfg(test)]
    if !crate::submission::test_support::for_root(root.path()).transaction_boundary(false) {
        return Err(ErrorCode::StoreUnavailable.into());
    }
    if fail_commit {
        return Err(ErrorCode::StoreUnavailable.into());
    }
    sql(transaction.commit())?;
    #[cfg(test)]
    {
        // A test-only pause after commit must never manufacture a rejection.
        let _ = crate::submission::test_support::for_root(root.path()).transaction_boundary(true);
    }
    Ok(receipt)
}

pub(super) fn probe_committed(
    connection: &mut Connection,
    auth: AuthContext,
    key: IdempotencyKey,
    request: JobRequest,
) -> Result<Option<AcceptanceReceipt>> {
    let transaction = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
    let result = probe(&transaction, &auth, &key, &request);
    sql(transaction.commit())?;
    result
}
