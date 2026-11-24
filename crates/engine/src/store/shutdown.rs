//! Durable shutdown operations: request, signal, progress, completion and
//! operation reads. Both barriers also mark running attempts with durable
//! engine-shutdown stop intent in the same transaction (WE-P07/3).

use super::*;

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

pub(super) fn request_shutdown(
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
    // WE-P07/3: the barrier and every running attempt's stop intent commit
    // together, so publication sees either neither or both.
    execution::mark_shutdown_intent(&transaction)?;
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

pub(super) fn shutdown_fingerprint(instance_id: &InstanceId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"core-shutdown-v1\n");
    hasher.update(instance_id.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.finalize().into()
}

pub(super) fn signal_shutdown(
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
    execution::mark_shutdown_intent(&transaction)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(operation_id)
}

pub(super) fn mark_shutdown_running(
    connection: &mut Connection,
    operation_id: &str,
) -> Result<(), CoreError> {
    connection
        .execute(
            "UPDATE core_operations SET state='running',phase='running',updated_at_ms=?2
             WHERE operation_id=?1 AND state='queued' AND phase='accepted'",
            rusqlite::params![operation_id, now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

pub(super) fn mark_shutdown_quiescing(
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

pub(super) fn show_operation(
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

pub(super) fn complete_shutdown(
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
