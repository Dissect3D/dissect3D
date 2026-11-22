//! Durable client credentials: enrollment, authentication, grant checks and
//! self-revocation.

use super::*;

pub(super) struct ExistingCredential {
    client_id: String,
    enrollment_id: String,
    digest: Vec<u8>,
    grant_policy: String,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
}

pub(super) fn enroll(
    connection: &mut Connection,
    enrollment: VerifiedEnrollment,
) -> Result<EnrollmentReceipt, CoreError> {
    if cfg!(windows) && enrollment.grant_policy == GrantPolicy::ExecutionV1 {
        return Err(CoreError::Busy);
    }
    if current_owner_identity().map_err(CoreError::Platform)? != enrollment.owner {
        return Err(CoreError::Unauthorized);
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let identity = read_identity(&tx)?;
    if identity.installation_id != enrollment.installation_id
        || identity.instance_id != enrollment.instance_id
    {
        return Err(CoreError::Conflict);
    }
    let existing:Option<ExistingCredential>=tx.query_row(
        "SELECT client_id,enrollment_id,secret_digest,grant_policy,created_at_ms,revoked_at_ms FROM credentials WHERE enrollment_id=?1 OR client_id=?2 LIMIT 1",
        rusqlite::params![enrollment.enrollment_id.as_str(),enrollment.client_id.as_str()],|row|Ok(ExistingCredential {client_id:row.get(0)?,enrollment_id:row.get(1)?,digest:row.get(2)?,grant_policy:row.get(3)?,created_at_ms:row.get(4)?,revoked_at_ms:row.get(5)?})).optional().map_err(|_|CoreError::StoreUnavailable)?;
    // Execution enrollment uses the enrollment ID's disjoint namespace. A public
    // aut_ reauthorization can never impersonate an original enrollment policy.
    let enrollment_authority = enrollment.enrollment_id.as_str();
    let base_policy = enrollment.grant_policy.storage_policy();
    if let Some(existing) = existing {
        use subtle::ConstantTimeEq as _;
        let stored_policy =
            GrantPolicy::parse(&existing.grant_policy).ok_or(CoreError::InvalidStore)?;
        if existing.client_id != enrollment.client_id.as_str()
            || existing.enrollment_id != enrollment.enrollment_id.as_str()
            || stored_policy != base_policy
            || existing.digest.len() != 32
            || existing
                .digest
                .as_slice()
                .ct_eq(enrollment.token_digest.as_bytes().as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(CoreError::Conflict);
        }
        if existing.revoked_at_ms.is_some() {
            return Err(CoreError::Unauthorized);
        }
        let original_execution:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM client_authorizations WHERE authorization_id=?1 AND client_id=?2 AND grant_policy='execution-v1')",rusqlite::params![enrollment_authority,enrollment.client_id.as_str()],|r|r.get(0)).map_err(|_|CoreError::StoreUnavailable)?;
        if (enrollment.grant_policy == GrantPolicy::ExecutionV1) != original_execution {
            return Err(CoreError::Conflict);
        }
        let grants = read_grants(&tx, &enrollment.client_id)?;
        validate_grants_for_policy(base_policy, &grants)?;
        // Old receipt replay retains its original policy facts. Auth status is
        // the separate source for effective grants after explicit authorization.
        let effective =
            reauthorization::effective_grants(&tx, &enrollment.client_id, grants.clone())?;
        let grants = if enrollment.grant_policy == GrantPolicy::ExecutionV1 {
            effective
        } else {
            grants
        };
        let receipt = enrollment_receipt(
            enrollment.installation_id,
            enrollment.client_id,
            enrollment.enrollment_id,
            grants,
            existing.created_at_ms,
            true,
        )?;
        tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
        return Ok(receipt);
    }
    let count: i64 = tx
        .query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if count >= MAX_CREDENTIAL_ROWS {
        return Err(CoreError::LimitReached);
    }
    let now = now_ms()?;
    tx.execute("INSERT INTO credentials(client_id,enrollment_id,secret_digest,client_kind,grant_policy,created_at_ms) VALUES(?1,?2,?3,'cli',?4,?5)",rusqlite::params![enrollment.client_id.as_str(),enrollment.enrollment_id.as_str(),enrollment.token_digest.as_bytes().as_slice(),base_policy.as_str(),now]).map_err(|_|CoreError::StoreUnavailable)?;
    for grant in base_policy.grants() {
        tx.execute(
            "INSERT INTO credential_grants(client_id,operation) VALUES(?1,?2)",
            rusqlite::params![enrollment.client_id.as_str(), grant],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    }
    if enrollment.grant_policy == GrantPolicy::ExecutionV1 {
        reauthorization::insert_authorization(
            &tx,
            enrollment_authority,
            &enrollment.client_id,
            now,
        )?;
    }
    let receipt = enrollment_receipt(
        enrollment.installation_id,
        enrollment.client_id,
        enrollment.enrollment_id,
        enrollment
            .grant_policy
            .grants()
            .iter()
            .map(|g| (*g).to_owned())
            .collect(),
        now,
        false,
    )?;
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    Ok(receipt)
}

pub(super) fn authenticate(
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
    let grants = reauthorization::effective_grants(&transaction, &client_id, grants)?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(AuthContext {
        installation_id: identity.installation_id,
        client_id,
        granted_operations: grants,
    })
}

pub(super) fn require_active_grant(
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

pub(super) fn revoke_self(
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

pub(super) fn read_grants(
    connection: &Connection,
    client_id: &ClientId,
) -> Result<Vec<String>, CoreError> {
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

pub(super) fn read_validated_grants(
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
    reauthorization::effective_grants(connection, client_id, grants)
}

pub(super) fn validate_grants_for_policy(
    policy: GrantPolicy,
    grants: &[String],
) -> Result<(), CoreError> {
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

pub(super) fn enrollment_receipt(
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
