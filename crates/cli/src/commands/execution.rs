//! Execution-aware command preflight, mode selection (`we-0.1` vs Stage 3),
//! and shared error mapping for execution routes.

pub(crate) mod request;
pub(crate) mod submit;

#[cfg(test)]
#[path = "execution/retry_save_regressions.rs"]
mod retry_save_regressions;

use crate::args::JobDefinitionArgs;
use crate::commands::{CommandError, CommandErrorContext};
use dissect3d_api::{
    Client, ClientError, ErrorCode, ExecutionCapability, SubmissionClientError, SubmissionId,
};

#[derive(Clone, Debug)]
pub(crate) enum ExecutionMode {
    Negotiated {
        capability: ExecutionCapability,
        granted_operations: Vec<String>,
    },
    Stage3,
}

/// Probe `/v1/info` once and select negotiated `we-0.1` or legacy Stage 3 mode.
pub(crate) async fn detect_mode(client: &Client) -> Result<ExecutionMode, CommandError> {
    let (mode, _) = detect_mode_with_info(client).await?;
    Ok(mode)
}

/// Probe `/v1/info` once and return both the selected mode and the core
/// `EngineInfo` so Stage 3 fallback does not repeat the initial `/v1/info` call.
pub(crate) async fn detect_mode_with_info(
    client: &Client,
) -> Result<(ExecutionMode, dissect3d_api::EngineInfo), CommandError> {
    let info = client
        .execution_info()
        .await
        .map_err(execution_client_error)?;
    let mode = match info.job_execution {
        Some(capability) => ExecutionMode::Negotiated {
            capability,
            granted_operations: info.core.granted_operations.clone(),
        },
        None => ExecutionMode::Stage3,
    };
    Ok((mode, info.core))
}

/// Verify both engine capability and credential grants before opening inputs or
/// sending an execution mutation.
pub(crate) fn require_execution_ops(
    capability: &ExecutionCapability,
    granted_operations: &[String],
    required_ops: &[&str],
) -> Result<(), CommandError> {
    for &op in required_ops {
        if !capability.operations.iter().any(|s| s == op) {
            return Err(operation_unavailable(
                "This execution operation is unavailable on the selected engine",
            ));
        }
        if !granted_operations.iter().any(|s| s == op) {
            return Err(CommandError {
                category: "unauthorized",
                message: "This credential lacks permission for this execution operation",
                exit_code: 4,
                context: Some(Box::new(CommandErrorContext {
                    accepted: Some(serde_json::Value::Bool(false)),
                    ..Default::default()
                })),
            });
        }
    }
    Ok(())
}

/// Pre-config validation for `jobs submit` and `run` so exit `2` `usage_error`
/// envelopes name the real command even when no config file exists.
pub(crate) fn preflight_definition(
    command: &str,
    args: &JobDefinitionArgs,
    json: bool,
) -> Option<i32> {
    if let Err(error) = request::preflight_args(args) {
        let outcome = crate::output::CommandOutcome::failure_with_context(
            command,
            crate::output::ErrorInfo::new(error.category, error.message),
            Some(serde_json::Value::Bool(false)),
            None,
            None,
        );
        crate::output::render(&outcome, json);
        return Some(error.exit_code);
    }
    None
}

pub(crate) fn operation_unavailable(message: &'static str) -> CommandError {
    CommandError {
        category: "operation_unavailable",
        message,
        exit_code: 5,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(false)),
            ..Default::default()
        })),
    }
}

pub(crate) fn usage_error(message: &'static str) -> CommandError {
    CommandError {
        category: "usage_error",
        message,
        exit_code: 2,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(false)),
            ..Default::default()
        })),
    }
}

pub(crate) fn execution_client_error(error: ClientError) -> CommandError {
    match error {
        ClientError::Rejected(ErrorCode::NotFound) => CommandError {
            category: "not_found",
            message: "The requested job was not found",
            exit_code: 19,
            context: None,
        },
        ClientError::Rejected(
            ErrorCode::OperationUnavailable
            | ErrorCode::IncompatibleContract
            | ErrorCode::IncompatibleProfile,
        )
        | ClientError::Incompatible => CommandError {
            category: "operation_unavailable",
            message: "Execution operation is unavailable or incompatible on this engine",
            exit_code: 5,
            context: None,
        },
        ClientError::Rejected(ErrorCode::JobCursorExpired) => CommandError {
            category: "job_cursor_expired",
            message: "The job list cursor expired; start listing from the beginning",
            exit_code: 19,
            context: None,
        },
        other => {
            let mut mapped = super::submission::before_client_error(other);
            if let Some(context) = &mut mapped.context {
                context.accepted = None;
            }
            mapped
        }
    }
}

pub(crate) fn execution_send_error(
    error: SubmissionClientError,
    sub_id: &SubmissionId,
    key: &dissect3d_api::IdempotencyKey,
    recovering_unknown: bool,
) -> CommandError {
    match error {
        SubmissionClientError::BeforeSend(inner) => {
            let mut mapped = execution_client_error(inner);
            mapped.context.get_or_insert_with(Default::default).accepted =
                Some(if recovering_unknown {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Bool(false)
                });
            mapped
        }
        SubmissionClientError::CancelledBeforeSend => CommandError {
            category: "interrupted",
            message: "Interrupted before the request was sent",
            exit_code: 18,
            context: Some(Box::new(CommandErrorContext {
                accepted: Some(if recovering_unknown {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::Bool(false)
                }),
                data: Some(serde_json::json!({ "sub_id": sub_id })),
                ..Default::default()
            })),
        },
        SubmissionClientError::Uncertain { correlation_id } => {
            let mut data = serde_json::json!({
                "sub_id": sub_id,
                "idempotency_key": key,
            });
            if let Some(corr) = correlation_id {
                data["correlation_id"] = serde_json::json!(corr);
            }
            CommandError {
                category: "submission_uncertain",
                message: "Acceptance is uncertain; run `dissect3d jobs recover <sub_id>` to reconcile with the same key",
                exit_code: 15,
                context: Some(Box::new(CommandErrorContext {
                    accepted: Some(serde_json::Value::Null),
                    data: Some(data),
                    ..Default::default()
                })),
            }
        }
        SubmissionClientError::Rejected(rejection) => {
            let mut data = serde_json::json!({
                "sub_id": sub_id,
                "idempotency_key": key,
                "correlation_id": rejection.error.correlation_id,
            });
            if let Some(details) = &rejection.error.details
                && !details.is_null()
            {
                data["details"] = details.clone();
            }
            let precedes_binding = matches!(
                rejection.error.code,
                ErrorCode::Unauthorized
                    | ErrorCode::Forbidden
                    | ErrorCode::CapacityExceeded
                    | ErrorCode::Busy
                    | ErrorCode::PersistenceUnavailable
                    | ErrorCode::StorageUnavailable
                    | ErrorCode::StoreUnavailable
                    | ErrorCode::EngineStopping
            );
            let accepted = if recovering_unknown && precedes_binding {
                serde_json::Value::Null
            } else {
                serde_json::Value::Bool(false)
            };
            let (category, message, exit_code) = match rejection.error.code {
                ErrorCode::Unauthorized => ("unauthorized", "This profile is not authorized", 4),
                ErrorCode::Forbidden => (
                    "unauthorized",
                    "This credential lacks permission for this execution operation",
                    4,
                ),
                ErrorCode::NotFound => ("not_found", "The requested job was not found", 19),
                ErrorCode::IncompatibleContract | ErrorCode::IncompatibleProfile => (
                    "operation_unavailable",
                    "The engine execution contract or profile is incompatible",
                    5,
                ),
                ErrorCode::OperationUnavailable => (
                    "operation_unavailable",
                    "This execution operation is unavailable on the selected engine",
                    5,
                ),
                ErrorCode::NotPrepared => (
                    "not_prepared",
                    "The selected model or runtime is not prepared",
                    6,
                ),
                ErrorCode::CapacityExceeded | ErrorCode::Busy => (
                    "capacity_rejected",
                    "The engine could not admit the request due to capacity limits",
                    7,
                ),
                ErrorCode::IdempotencyConflict => (
                    "idempotency_conflict",
                    "This idempotency key was already used for a different request",
                    19,
                ),
                ErrorCode::JobNotTerminal => {
                    ("job_not_terminal", "Only terminal jobs can be retried", 19)
                }
                ErrorCode::RetryPrerequisiteUnavailable => (
                    "retry_prerequisite_unavailable",
                    "A prerequisite required to retry this job is no longer available",
                    19,
                ),
                ErrorCode::CleanupUnconfirmed => (
                    "cleanup_unconfirmed",
                    "Prior attempt cleanup is not yet confirmed",
                    19,
                ),
                ErrorCode::InvalidRequest
                | ErrorCode::InvalidInput
                | ErrorCode::UnsupportedParameter
                | ErrorCode::AmbiguousSelection
                | ErrorCode::RequiredFeatureUnsupported => {
                    ("invalid_request", "The engine rejected the request", 2)
                }
                ErrorCode::PersistenceUnavailable
                | ErrorCode::StorageUnavailable
                | ErrorCode::StoreUnavailable => (
                    "storage_unavailable",
                    "The engine could not complete the request because storage is unavailable",
                    7,
                ),
                ErrorCode::EngineStopping => (
                    "engine_unavailable",
                    "The engine is stopping and could not complete the request",
                    3,
                ),
                _ => (
                    "request_failed",
                    "The engine rejected the execution request",
                    19,
                ),
            };
            CommandError {
                category,
                message,
                exit_code,
                context: Some(Box::new(CommandErrorContext {
                    accepted: Some(accepted),
                    data: Some(data),
                    ..Default::default()
                })),
            }
        }
    }
}
