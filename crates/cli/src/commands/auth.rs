//! `auth setup`: credential generation and native enrollment.

use super::*;

pub(super) fn setup(
    profile: &Profile,
    engine: &crate::connection::DiscoveredEngine,
    submission_access_requested: bool,
) -> Result<serde_json::Value, CommandError> {
    let mut reused = false;
    let mut credential = match profile.load().map_err(CommandError::connection)? {
        Some(mut existing)
            if existing.installation_id == engine.discovery.installation_id
                && existing.state == "pending" =>
        {
            // Pending identity and secret are durable before transport. Reuse
            // them exactly so a lost receipt can only replay the same request.
            existing.instance_id = engine.discovery.instance_id.clone();
            reused = true;
            existing
        }
        Some(existing)
            if existing.installation_id == engine.discovery.installation_id
                && existing.state == "active" =>
        {
            let mut existing = existing;
            existing.instance_id = engine.discovery.instance_id.clone();
            let client = engine.client(existing).map_err(CommandError::connection)?;
            match tokio_runtime().block_on(client.auth_status()) {
                Ok(status) if status.active => {
                    return serde_json::to_value(status).map_err(|_| invalid_error());
                }
                Err(dissect3d_api::ClientError::Rejected(
                    dissect3d_api::ErrorCode::Unauthorized,
                )) => {}
                Err(_) => return Err(transport_error()),
                _ => return Err(unauthorized()),
            }
            new_credential(engine, false)?
        }
        _ => new_credential(engine, submission_access_requested)?,
    };
    if credential.submission_access {
        // `connection` already completed protected discovery, process matching,
        // and the old native probe. This separate same-owner exchange gates
        // both first enrollment and replay of a pending opt-in record.
        engine
            .supports_submission_access()
            .map_err(CommandError::connection)?;
    }
    save_before_enroll(&credential, reused, |record| profile.save(record))?;
    let receipt = if credential.submission_access {
        engine.enroll_submission(&credential)
    } else {
        engine.enroll(&credential)
    }
    .map_err(|error| enrollment_error(error, &credential))?;
    credential.state = "active".to_owned();
    profile
        .save(&credential)
        .map_err(|error| enrollment_error(error, &credential))?;
    serde_json::to_value(receipt).map_err(|_| invalid_error())
}

/// Save the pending credential before enrollment. A credential retained from
/// an earlier attempt may already have been enrolled, so its save failure is
/// "acceptance unknown" (`CSD-05`); a fresh one keeps the connection mapping.
pub(super) fn save_before_enroll(
    credential: &ProfileCredential,
    reused: bool,
    save: impl FnOnce(&ProfileCredential) -> Result<(), ConnectionError>,
) -> Result<(), CommandError> {
    save(credential).map_err(|error| {
        if !reused {
            return CommandError::connection(error);
        }
        CommandError::recovery_save_failure(
            RequestAcceptance::Unknown,
            "An earlier enrollment may have committed, but its pending credential could not be saved",
            serde_json::json!({
                "client_id": credential.client_id,
                "enrollment_id": credential.enrollment_id
            }),
        )
    })
}

fn new_credential(
    engine: &crate::connection::DiscoveredEngine,
    submission_access: bool,
) -> Result<ProfileCredential, CommandError> {
    let installation_id = engine.discovery.installation_id.clone();
    let instance_id = engine.discovery.instance_id.clone();
    let (client_id, enrollment_id, secret_hex) = random_material()?;
    Ok(ProfileCredential {
        installation_id,
        instance_id,
        client_id,
        enrollment_id,
        secret_hex,
        state: "pending".to_owned(),
        submission_access,
    })
}

fn random_material() -> Result<(ClientId, EnrollmentId, String), CommandError> {
    let mut ids = [0_u8; 32];
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut ids)
        .and_then(|()| getrandom::fill(&mut secret))
        .map_err(|_| CommandError {
            category: "entropy_unavailable",
            message: "Secure credential generation is unavailable",
            exit_code: 6,
            context: None,
        })?;
    let client =
        ClientId::parse(format!("cli_{}", hex(&ids[..16]))).map_err(|_| invalid_error())?;
    let enrollment =
        EnrollmentId::parse(format!("enr_{}", hex(&ids[16..]))).map_err(|_| invalid_error())?;
    ids.fill(0);
    let encoded = hex(&secret);
    secret.fill(0);
    Ok((client, enrollment, encoded))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 15) as usize] as char);
    }
    encoded
}
