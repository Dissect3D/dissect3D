//! Explicit native-authorized grants layered over unchanged legacy credentials.
use super::*;
use dissect3d_platform::OwnerIdentity;
use subtle::ConstantTimeEq;

pub(crate) struct VerifiedAuthorization {
    pub(crate) owner: OwnerIdentity,
    pub(crate) installation_id: InstallationId,
    pub(crate) instance_id: InstanceId,
    pub(crate) client_id: ClientId,
    pub(crate) token_digest: TokenDigest,
    pub(crate) authorization_id: String,
}
pub(crate) use dissect3d_api::ExecutionAuthorizationReceipt as AuthorizationReceipt;

pub(super) fn insert_authorization(
    tx: &Transaction<'_>,
    id: &str,
    client: &ClientId,
    now: i64,
) -> Result<(), CoreError> {
    let count: i64 = tx
        .query_row("SELECT count(*) FROM client_authorizations", [], |r| {
            r.get(0)
        })
        .map_err(|_| CoreError::StoreUnavailable)?;
    if count >= MAX_CREDENTIAL_ROWS {
        return Err(CoreError::LimitReached);
    }
    tx.execute(
        "INSERT INTO client_authorizations VALUES(?1,?2,'execution-v1',?3)",
        rusqlite::params![id, client.as_str(), now],
    )
    .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

pub(super) fn effective_grants(
    db: &Connection,
    client: &ClientId,
    base: Vec<String>,
) -> Result<Vec<String>, CoreError> {
    let (authorized,invalid):(bool,bool)=db.query_row(
        "SELECT EXISTS(SELECT 1 FROM client_authorizations WHERE client_id=?1),EXISTS(SELECT 1 FROM client_authorizations WHERE client_id=?1 AND grant_policy<>'execution-v1')",
        [client.as_str()],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|_|CoreError::StoreUnavailable)?;
    if invalid {
        return Err(CoreError::InvalidStore);
    }
    if !authorized {
        return Ok(base);
    }
    Ok(crate::credentials::EXECUTION_GRANTS
        .iter()
        .map(|g| (*g).to_owned())
        .collect())
}

pub(super) fn authorize(
    db: &mut Connection,
    request: VerifiedAuthorization,
) -> Result<AuthorizationReceipt, CoreError> {
    let suffix = request
        .authorization_id
        .strip_prefix("aut_")
        .ok_or(CoreError::Conflict)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoreError::Conflict);
    }
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    let identity = read_identity(&tx)?;
    if request.owner != current_owner_identity().map_err(CoreError::Platform)?
        || request.installation_id != identity.installation_id
        || request.instance_id != identity.instance_id
    {
        return Err(CoreError::Unauthorized);
    }
    let credential: Option<(Vec<u8>, Option<i64>)> = tx
        .query_row(
            "SELECT secret_digest,revoked_at_ms FROM credentials WHERE client_id=?1",
            [request.client_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let (digest, revoked) = credential.ok_or(CoreError::Unauthorized)?;
    if revoked.is_some()
        || digest.len() != 32
        || digest
            .as_slice()
            .ct_eq(request.token_digest.as_bytes().as_slice())
            .unwrap_u8()
            != 1
    {
        return Err(CoreError::Unauthorized);
    }
    // Validate the underlying closed legacy policy before allowing an upgrade.
    let _ = read_validated_grants(&tx, &request.client_id)?;
    let previous: Option<String> = tx
        .query_row(
            "SELECT client_id FROM client_authorizations WHERE authorization_id=?1",
            [&request.authorization_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let replayed = previous.is_some();
    if previous.is_some_and(|client| client != request.client_id.as_str()) {
        return Err(CoreError::Conflict);
    }
    if !replayed {
        insert_authorization(
            &tx,
            &request.authorization_id,
            &request.client_id,
            now_ms()?,
        )?;
    }
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    Ok(AuthorizationReceipt {
        bootstrap_version: "1.0".into(),
        contract_version: dissect3d_api::EXECUTION_AUTHORIZATION_CONTRACT.into(),
        installation_id: identity.installation_id,
        client_id: request.client_id,
        authorization_id: request.authorization_id,
        grant_policy: "execution-v1".into(),
        granted_operations: crate::credentials::EXECUTION_GRANTS
            .iter()
            .map(|g| (*g).to_owned())
            .collect(),
        replayed,
    })
}

impl Store {
    pub(crate) fn authorize_execution(
        &self,
        request: VerifiedAuthorization,
    ) -> Result<AuthorizationReceipt, CoreError> {
        if request.authorization_id.len() != 36 {
            return Err(CoreError::Conflict);
        }
        self.request(|reply| Command::AuthorizeExecution(request, reply))
    }
}
