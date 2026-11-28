//! `auth authorize --execution-access`: explicit same-client native
//! reauthorization (`WE-006`) and `CR-CS-01` exit classification.

use super::*;
use crate::connection::ControlLease;
use crate::connection::execution::AuthorizationFailure;

pub(super) fn authorize_execution(
    profile: &Profile,
    lease: &ControlLease<'_>,
    engine: &crate::connection::DiscoveredEngine,
) -> Result<serde_json::Value, CommandError> {
    engine
        .supports_execution_access()
        .map_err(map_before_send)?;
    let receipt = profile
        .with_execution_authorization(Some(lease), |credential, pending| {
            engine.authorize_execution(credential, pending)
        })
        .map_err(map_authorization_failure)?;
    serde_json::to_value(receipt).map_err(|_| invalid_error())
}

pub(super) fn map_before_send(error: ConnectionError) -> CommandError {
    if error == ConnectionError::Incompatible {
        return CommandError {
            category: "operation_unavailable",
            message: "Execution authorization is unavailable on the selected engine or platform",
            exit_code: 5,
            context: None,
        };
    }
    CommandError::connection(error)
}

pub(super) fn map_authorization_failure(failure: AuthorizationFailure) -> CommandError {
    match failure {
        AuthorizationFailure::BeforeSend(error) => map_before_send(error),
        AuthorizationFailure::RecordRewrite {
            client_id,
            authorization_id,
        } => CommandError::recovery_save_failure(
            RequestAcceptance::Unknown,
            "An earlier execution authorization may have committed, but its pending record could not be saved",
            serde_json::json!({
                "client_id": client_id,
                "authorization_id": authorization_id,
            }),
        ),
        AuthorizationFailure::AfterWrite {
            error:
                error @ (ConnectionError::Unauthorized
                | ConnectionError::Capacity
                | ConnectionError::Conflict
                | ConnectionError::EnrollmentRejected),
            ..
        } => CommandError::connection(error),
        AuthorizationFailure::AfterWrite {
            client_id,
            authorization_id,
            ..
        } => CommandError {
            category: "setup_uncertain",
            message: "Execution authorization may have committed; repeat `dissect3d auth authorize --execution-access` with this profile to recover it",
            exit_code: 19,
            context: Some(Box::new(CommandErrorContext {
                data: Some(serde_json::json!({
                    "client_id": client_id,
                    "authorization_id": authorization_id,
                })),
                ..Default::default()
            })),
        },
        AuthorizationFailure::ReceiptUnsaved(receipt) => CommandError::recovery_save_failure(
            RequestAcceptance::Accepted { operation_id: None },
            "Execution authorization was accepted, but the local recovery record could not be saved",
            serde_json::json!({
                "client_id": receipt.client_id,
                "authorization_id": receipt.authorization_id,
                "grant_policy": receipt.grant_policy,
            }),
        ),
    }
}
