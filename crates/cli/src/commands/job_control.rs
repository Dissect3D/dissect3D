//! Explicit job control commands (`jobs cancel`, `jobs retry`).
//!
//! `jobs cancel` sends a single explicit cancel request without automatic retry
//! and reports cancellation intent separately from confirmed cleanup.
//! `jobs retry` persists a protected `1.1` pending retry record before `POST`
//! so lost replies can be recovered with the exact same key and source job.

use crate::commands::execution::submit::{
    ExecutionSubmissionSuccess, parse_or_generate_key, persist_fresh_execution_record, random_hex,
    send_execution_record,
};
use crate::commands::execution::{
    ExecutionMode, detect_mode, execution_client_error, operation_unavailable,
    require_execution_ops, usage_error,
};
use crate::commands::{CommandError, CommandErrorContext, data_root, tokio_runtime};
use crate::config::ConfigFile;
use crate::connection::Profile;
use crate::submissions::execution::PendingExecutionRecord;
use dissect3d_api::{
    CancelResponse, ClientLimits, ErrorCode, JOB_CONTRACT, JobId, SubmissionClientError,
    SubmissionId,
};
use std::path::Path;

pub(crate) fn cancel(
    job_id: String,
    config: &ConfigFile,
    config_path: &Path,
    limits: ClientLimits,
) -> Result<CancelResponse, CommandError> {
    let id = JobId::parse(job_id).map_err(|_| usage_error("Job ID is invalid"))?;
    super::discovery::connected(config, config_path, limits, |client| {
        let runtime = tokio_runtime();
        runtime.block_on(async {
            let mode = detect_mode(&client).await?;
            let ExecutionMode::Negotiated {
                capability,
                granted_operations,
            } = mode
            else {
                return Err(operation_unavailable(
                    "Job cancellation requires an execution-capable engine",
                ));
            };
            require_execution_ops(&capability, &granted_operations, &["jobs.cancel"])?;
            client
                .cancel_execution_job_with(&capability, &id)
                .await
                .map_err(|error| cancel_send_error(error, &id))
        })
    })
}

pub(crate) fn retry(
    job_id: String,
    idempotency_key: Option<String>,
    config: &ConfigFile,
    config_path: &Path,
    limits: ClientLimits,
) -> Result<ExecutionSubmissionSuccess, CommandError> {
    let source_id = JobId::parse(job_id).map_err(|_| usage_error("Job ID is invalid"))?;
    let key = parse_or_generate_key(idempotency_key.as_deref())?;

    let root = data_root(config, config_path).ok_or_else(|| CommandError {
        category: "engine_unavailable",
        message: "Configure an engine connection before retrying a job",
        exit_code: 3,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(false)),
            ..Default::default()
        })),
    })?;
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let engine = profile
        .connection(&root, limits.connect_timeout, limits)
        .map_err(CommandError::connection)?;
    let credential = profile
        .credential_snapshot(config, &engine)
        .map_err(CommandError::connection)?;
    let installation_id = credential.installation_id.clone();
    let client_id = credential.client_id.clone();
    let client = engine
        .client(credential)
        .map_err(CommandError::connection)?;

    let runtime = tokio_runtime();
    runtime.block_on(async {
        let mode = detect_mode(&client).await?;
        let ExecutionMode::Negotiated {
            capability,
            granted_operations,
        } = mode
        else {
            return Err(operation_unavailable(
                "Job retry requires an execution-capable engine",
            ));
        };
        require_execution_ops(&capability, &granted_operations, &["jobs.retry"])?;

        let sub_id = SubmissionId::parse(format!("sub_{}", random_hex()?))
            .map_err(|_| usage_error("Could not generate submission ID"))?;
        let record = PendingExecutionRecord {
            record_version: "1.1".into(),
            sub_id,
            installation_id,
            client_id,
            operation: "jobs.retry".into(),
            key,
            job_contract: JOB_CONTRACT.into(),
            request_body_utf8: None,
            source_job_id: Some(source_id),
            input_identities: Vec::new(),
            receipt: None,
        };
        let record_lease = persist_fresh_execution_record(&profile, &record)?;
        send_execution_record(&client, &capability, &record_lease, &record, false).await
    })
}

pub(crate) fn cancel_send_error(error: SubmissionClientError, job_id: &JobId) -> CommandError {
    match error {
        SubmissionClientError::BeforeSend(inner) => execution_client_error(inner),
        SubmissionClientError::CancelledBeforeSend => CommandError {
            category: "interrupted",
            message: "Interrupted before the cancel request was sent",
            exit_code: 18,
            context: Some(Box::new(CommandErrorContext {
                data: Some(serde_json::json!({ "job_id": job_id })),
                ..Default::default()
            })),
        },
        SubmissionClientError::Uncertain { correlation_id } => {
            let mut data = serde_json::json!({ "job_id": job_id });
            if let Some(corr) = correlation_id {
                data["correlation_id"] = serde_json::json!(corr);
            }
            CommandError {
                category: "cancel_uncertain",
                message: "Cancel request outcome is uncertain; check `dissect3d jobs show` or repeat `dissect3d jobs cancel`",
                exit_code: 19,
                context: Some(Box::new(CommandErrorContext {
                    data: Some(data),
                    ..Default::default()
                })),
            }
        }
        SubmissionClientError::Rejected(rejection) => {
            let mut data = serde_json::json!({
                "job_id": job_id,
                "correlation_id": rejection.error.correlation_id,
            });
            if let Some(details) = &rejection.error.details
                && !details.is_null()
            {
                data["details"] = details.clone();
            }
            let (category, message, exit_code) = match rejection.error.code {
                ErrorCode::Unauthorized => ("unauthorized", "This profile is not authorized", 4),
                ErrorCode::Forbidden => (
                    "unauthorized",
                    "This credential lacks permission to cancel this job",
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
                    "Job cancellation is unavailable on the selected engine",
                    5,
                ),
                ErrorCode::CapacityExceeded | ErrorCode::Busy => (
                    "capacity_rejected",
                    "The engine could not admit the cancel request due to capacity limits",
                    7,
                ),
                ErrorCode::PersistenceUnavailable
                | ErrorCode::StorageUnavailable
                | ErrorCode::StoreUnavailable => (
                    "storage_unavailable",
                    "The engine could not complete cancellation because storage is unavailable",
                    7,
                ),
                ErrorCode::EngineStopping => (
                    "engine_unavailable",
                    "The engine is stopping and could not complete cancellation",
                    3,
                ),
                ErrorCode::CleanupUnconfirmed => (
                    "cleanup_unconfirmed",
                    "Prior attempt cleanup is not yet confirmed",
                    19,
                ),
                ErrorCode::InvalidRequest => (
                    "invalid_request",
                    "The engine rejected the cancel request",
                    2,
                ),
                _ => (
                    "request_failed",
                    "The engine rejected the cancel request",
                    19,
                ),
            };
            CommandError {
                category,
                message,
                exit_code,
                context: Some(Box::new(CommandErrorContext {
                    data: Some(data),
                    ..Default::default()
                })),
            }
        }
    }
}
