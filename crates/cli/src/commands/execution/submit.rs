//! Negotiated `we-0.1` submission, pending-before-send persistence, receipt
//! saving (`CR-CS-01`), and `jobs recover` routing across `1.0` and `1.1` records.

use super::request::ExecutionRequest;
use super::{
    ExecutionMode, detect_mode, detect_mode_with_info, execution_client_error,
    execution_send_error, operation_unavailable, require_execution_ops, usage_error,
};
use crate::args::JobDefinitionArgs;
use crate::commands::{
    CommandError, CommandErrorContext, RequestAcceptance, data_root, tokio_runtime,
};
use crate::config::ConfigFile;
use crate::connection::Profile;
use crate::submissions::execution::{ExecutionRecordLease, PendingExecutionRecord};
use crate::submissions::{AnyPendingRecord, RecordError, SubmissionRecords};
use dissect3d_api::{
    Client, ClientLimits, ExecutionAcceptance, ExecutionCapability, ExecutionSubmissionBody,
    IdempotencyKey, InputRef, JOB_CONTRACT, ModelLookup, ObservationScope, PageQuery, SubmissionId,
    SubmittedTask, TaskKey, TaskListQuery,
};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, serde::Serialize)]
pub(crate) struct ExecutionSubmissionSuccess {
    pub(crate) sub_id: Option<SubmissionId>,
    #[serde(flatten)]
    pub(crate) receipt: ExecutionAcceptance,
}

/// Validated connection context for a negotiated `we-0.1` submission.
pub(crate) struct NegotiatedSubmitContext<'a> {
    pub(crate) profile: &'a Profile,
    pub(crate) client: &'a Client,
    pub(crate) capability: &'a ExecutionCapability,
    pub(crate) granted_operations: &'a [String],
    pub(crate) installation_id: dissect3d_api::InstallationId,
    pub(crate) client_id: dissect3d_api::ClientId,
}

/// Entry point for `jobs submit` and `run --detach`.
///
/// Probes `/v1/info` once before opening any inputs. Uses the negotiated
/// `we-0.1` flow when the engine advertises `job_execution`; otherwise rejects
/// execution-only options with exit `5` or delegates unchanged to Stage 3.
pub(crate) fn submit_or_stage3(
    args: JobDefinitionArgs,
    config: &ConfigFile,
    config_path: &Path,
    limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    let cwd = std::env::current_dir()
        .map_err(|_| usage_error("Current working directory is unavailable"))?;
    let (request, policy) = ExecutionRequest::from_args(&args, &cwd)?;
    let requires_execution =
        request.requires_execution_contract(args.execution_timeout_ms.as_deref());
    let key = parse_or_generate_key(args.idempotency_key.as_deref())?;

    let root = data_root(config, config_path).ok_or_else(|| CommandError {
        category: "engine_unavailable",
        message: "Configure an engine connection before submitting",
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
    let (mode, core_info) = runtime.block_on(detect_mode_with_info(&client))?;
    match mode {
        ExecutionMode::Stage3 => {
            if requires_execution {
                return Err(operation_unavailable(
                    "Execution-aware submission requires an engine advertising job_execution",
                ));
            }
            let result = super::super::submission::submit_with_info(
                args,
                config,
                config_path,
                limits,
                Some(core_info),
            )?;
            serde_json::to_value(result).map_err(|_| super::super::invalid_error())
        }
        ExecutionMode::Negotiated {
            capability,
            granted_operations,
        } => {
            let ctx = NegotiatedSubmitContext {
                profile: &profile,
                client: &client,
                capability: &capability,
                granted_operations: &granted_operations,
                installation_id,
                client_id,
            };
            let success = runtime.block_on(submit_negotiated(&ctx, key, &request, policy))?;
            serde_json::to_value(success).map_err(|_| super::super::invalid_error())
        }
    }
}

pub(crate) async fn submit_negotiated(
    ctx: &NegotiatedSubmitContext<'_>,
    key: IdempotencyKey,
    definition: &ExecutionRequest,
    policy: dissect3d_api::ExecutionPolicy,
) -> Result<ExecutionSubmissionSuccess, CommandError> {
    // Check capabilities, grants, and we-0.1 required_features before opening
    // or uploading any local input files.
    require_execution_ops(
        ctx.capability,
        ctx.granted_operations,
        &["inputs.create", "jobs.submit"],
    )?;
    definition.validate_execution_features()?;

    let mut model_selector = definition.model.clone();
    let declared = if definition.task.is_none() {
        let model = ctx
            .client
            .model(ModelLookup {
                selector: definition.model.clone(),
                ..Default::default()
            })
            .await
            .map_err(execution_client_error)?;
        model_selector = model.item.summary.support_ref;
        let tasks = ctx
            .client
            .tasks(TaskListQuery {
                page: PageQuery {
                    limit: Some(2),
                    cursor: None,
                },
                support_ref: Some(model_selector.clone()),
            })
            .await
            .map_err(execution_client_error)?;
        if tasks.next_cursor.is_some() {
            return Err(usage_error("Specify --task and --task-version"));
        }
        tasks
            .items
            .into_iter()
            .map(|task| SubmittedTask {
                id: task.task.id().to_owned(),
                version: task.task.version().to_owned(),
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let task = definition.select_task(&declared)?;
    definition.validate_selected_task(task.clone())?;
    let selected = ctx
        .client
        .model(ModelLookup {
            selector: model_selector.clone(),
            task: Some(
                TaskKey::new(&task.id, &task.version)
                    .map_err(|_| usage_error("Task ID or version is invalid"))?,
            ),
            runtime_ref: definition.runtime.clone(),
            variant: definition.variant.clone(),
        })
        .await
        .map_err(execution_client_error)?;
    let summary = selected.item.summary;
    let [observation] = summary.observations.as_slice() else {
        return Err(execution_client_error(
            dissect3d_api::ClientError::InvalidResponse,
        ));
    };
    let selection = &observation.selection;
    if observation.scope != ObservationScope::Selection
        || (definition.task.is_none() && summary.support_ref != model_selector)
        || selection["support_ref"] != summary.support_ref
        || selection["task"] != serde_json::json!(task)
        || selection["runtime_ref"].as_str().is_none_or(str::is_empty)
        || selection["variant"].as_str().is_none_or(str::is_empty)
        || definition
            .variant
            .as_ref()
            .is_some_and(|variant| selection["variant"] != *variant)
    {
        return Err(execution_client_error(
            dissect3d_api::ClientError::InvalidResponse,
        ));
    }

    let inputs = definition.open_inputs()?;
    let mut references: BTreeMap<String, Vec<InputRef>> = BTreeMap::new();
    let mut identities = Vec::new();
    for input in inputs {
        let receipt = ctx
            .client
            .create_execution_input_with(
                ctx.capability,
                tokio::fs::File::from_std(input.file),
                input.length,
                input.media_type,
            )
            .await
            .map_err(execution_client_error)?;
        references.entry(input.role).or_default().push(InputRef {
            input_id: receipt.identity.input_id.clone(),
        });
        identities.push(receipt.identity);
    }

    let body = definition.to_execution_body(task, references, policy)?;
    let body_utf8 = String::from_utf8(body.as_bytes().to_vec())
        .map_err(|_| usage_error("Execution request body must be valid UTF-8"))?;
    let sub_id = SubmissionId::parse(format!("sub_{}", random_hex()?))
        .map_err(|_| usage_error("Could not generate submission ID"))?;
    let record = PendingExecutionRecord {
        record_version: "1.1".into(),
        sub_id,
        installation_id: ctx.installation_id.clone(),
        client_id: ctx.client_id.clone(),
        operation: "jobs.submit".into(),
        key,
        job_contract: JOB_CONTRACT.into(),
        request_body_utf8: Some(body_utf8),
        source_job_id: None,
        input_identities: identities,
        receipt: None,
    };
    let record_lease = persist_fresh_execution_record(ctx.profile, &record)?;
    send_execution_record(ctx.client, ctx.capability, &record_lease, &record, false).await
}

/// Entry point for `jobs recover SUB_ID`, supporting both Stage 3 (`1.0`) and
/// execution (`1.1`) records.
pub(crate) fn recover_any(
    id: &str,
    config: &ConfigFile,
    config_path: &Path,
    limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    let sub_id = SubmissionId::parse(id).map_err(|_| usage_error("Submission ID is invalid"))?;
    let profile = SubmissionRecords::open_existing(config_path)
        .map_err(super::super::submission::record_error)?;
    let loaded = {
        let records =
            SubmissionRecords::lock(&profile).map_err(super::super::submission::record_error)?;
        records
            .load_any(&sub_id)
            .map_err(super::super::submission::record_error)?
    };
    match loaded {
        AnyPendingRecord::Stage3(record) => {
            let prior_receipt = record.receipt.clone();
            let wrap = |error: CommandError| {
                preserve_stage3_recovery_status(error, &record.sub_id, prior_receipt.as_ref())
            };
            let root = data_root(config, config_path).ok_or_else(|| {
                wrap(CommandError {
                    category: "engine_unavailable",
                    message: "Configure the original engine connection before recovery",
                    exit_code: 3,
                    context: Some(Box::new(CommandErrorContext {
                        accepted: Some(serde_json::Value::Null),
                        ..Default::default()
                    })),
                })
            })?;
            let engine = profile
                .connection(&root, limits.connect_timeout, limits)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            let credential = profile
                .credential_snapshot(config, &engine)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            if credential.installation_id != record.installation_id
                || credential.client_id != record.client_id
            {
                return Err(wrap(CommandError {
                    category: "recovery_identity_mismatch",
                    message: "Recovery requires the original installation and credential",
                    exit_code: 5,
                    context: Some(Box::new(CommandErrorContext {
                        accepted: Some(serde_json::Value::Bool(false)),
                        ..Default::default()
                    })),
                }));
            }
            let client = engine
                .client(credential)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            let runtime = tokio_runtime();
            match runtime.block_on(detect_mode(&client)) {
                Err(error) => Err(wrap(error)),
                Ok(ExecutionMode::Stage3) => {
                    let result =
                        super::super::submission::recover(id, config, config_path, limits)?;
                    serde_json::to_value(result).map_err(|_| super::super::invalid_error())
                }
                Ok(ExecutionMode::Negotiated { capability, .. }) => {
                    // WE-001: replay the exact Stage 3 body under `we-0.1` without
                    // rekeying, reuploading, or modifying the Stage 3 pending record.
                    let _lease = {
                        let records = SubmissionRecords::lock(&profile)
                            .map_err(|err| wrap(super::super::submission::record_error(err)))?;
                        records
                            .coordinate(&record)
                            .map_err(|err| wrap(super::super::submission::record_error(err)))?
                    };
                    let body = ExecutionSubmissionBody::replay(
                        record.request_body_utf8.as_bytes().to_vec(),
                    )
                    .map_err(|_| {
                        wrap(super::super::submission::record_error(RecordError::Invalid))
                    })?;
                    let receipt = runtime
                        .block_on(client.submit_execution_job_with(&capability, &record.key, &body))
                        .map_err(|error| {
                            let mapped = execution_send_error(
                                error,
                                &record.sub_id,
                                &record.key,
                                prior_receipt.is_none(),
                            );
                            if prior_receipt.is_some() {
                                wrap(mapped)
                            } else {
                                mapped
                            }
                        })?;
                    let success = ExecutionSubmissionSuccess {
                        sub_id: Some(record.sub_id),
                        receipt,
                    };
                    serde_json::to_value(success).map_err(|_| super::super::invalid_error())
                }
            }
        }
        AnyPendingRecord::Execution(record) => {
            let wrap = |error: CommandError| preserve_execution_recovery_status(error, &record);
            let record_lease = {
                let records = SubmissionRecords::lock(&profile).map_err(|error| {
                    if error == RecordError::Busy {
                        wrap(CommandError {
                            category: "profile_busy",
                            message: "Another command is updating this profile; retry after it completes",
                            exit_code: 7,
                            context: Some(Box::new(CommandErrorContext {
                                accepted: Some(serde_json::Value::Null),
                                ..Default::default()
                            })),
                        })
                    } else {
                        wrap(super::super::submission::record_error(error))
                    }
                })?;
                records
                    .coordinate_execution(&record)
                    .map_err(|err| wrap(super::super::submission::record_error(err)))?
            };
            let root = data_root(config, config_path).ok_or_else(|| {
                wrap(CommandError {
                    category: "engine_unavailable",
                    message: "Configure the original engine connection before recovery",
                    exit_code: 3,
                    context: Some(Box::new(CommandErrorContext {
                        accepted: Some(serde_json::Value::Null),
                        ..Default::default()
                    })),
                })
            })?;
            let engine = profile
                .connection(&root, limits.connect_timeout, limits)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            let credential = profile
                .credential_snapshot(config, &engine)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            if credential.installation_id != record.installation_id
                || credential.client_id != record.client_id
            {
                return Err(wrap(CommandError {
                    category: "recovery_identity_mismatch",
                    message: "Recovery requires the original installation and credential",
                    exit_code: 5,
                    context: Some(Box::new(CommandErrorContext {
                        accepted: Some(serde_json::Value::Bool(false)),
                        ..Default::default()
                    })),
                }));
            }
            let client = engine
                .client(credential)
                .map_err(|err| wrap(CommandError::connection(err)))?;
            let runtime = tokio_runtime();
            let mode = runtime.block_on(detect_mode(&client)).map_err(wrap)?;
            let capability = match require_execution_mode_for_record(&mode) {
                Ok(cap) => cap,
                Err(error) => {
                    return Err(if record.receipt.is_some() {
                        wrap(error)
                    } else {
                        error
                    });
                }
            };
            let success = runtime
                .block_on(send_execution_record(
                    &client,
                    capability,
                    &record_lease,
                    &record,
                    true,
                ))
                .map_err(|error| {
                    if record.receipt.is_some() {
                        preserve_execution_recovery_status(error, &record)
                    } else {
                        error
                    }
                })?;
            serde_json::to_value(success).map_err(|_| super::super::invalid_error())
        }
    }
}

/// Preserve known prior acceptance (`accepted: true` + lossless receipt) or
/// unknown prior acceptance (`accepted: null`) across Stage 3 recovery errors.
fn preserve_stage3_recovery_status(
    mut error: CommandError,
    sub_id: &SubmissionId,
    receipt: Option<&dissect3d_api::AcceptanceReceipt>,
) -> CommandError {
    if let Some(receipt) = receipt {
        if error.category == "submission_uncertain" {
            error.category = "recovery_confirmation_failed";
            error.message = "Job acceptance is known; the confirmation response was unavailable";
        }
        error.exit_code = 19;
        let data = super::super::submission::SubmissionSuccess {
            sub_id: Some(sub_id.clone()),
            receipt: receipt.clone(),
        };
        let raw_data = serde_json::value::to_raw_value(&data).ok();
        error.context = Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(true)),
            operation_id: None,
            data: None,
            raw_data,
        }));
    } else if error.exit_code != 5 {
        error.context.get_or_insert_with(Default::default).accepted = Some(serde_json::Value::Null);
    }
    error
}

/// Preserve known prior acceptance (`accepted: true` + lossless receipt) or
/// unknown prior acceptance (`accepted: null`) across `1.1` recovery errors.
pub(crate) fn preserve_execution_recovery_status(
    mut error: CommandError,
    record: &PendingExecutionRecord,
) -> CommandError {
    if error.category == "recovery_storage_failed" {
        return error;
    }
    if let Some(receipt) = &record.receipt {
        let data = ExecutionSubmissionSuccess {
            sub_id: Some(record.sub_id.clone()),
            receipt: receipt.clone(),
        };
        let raw_data = serde_json::value::to_raw_value(&data).ok();
        error.context = Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(true)),
            operation_id: None,
            data: None,
            raw_data,
        }));
    } else if error.exit_code != 5 {
        error.context.get_or_insert_with(Default::default).accepted = Some(serde_json::Value::Null);
    }
    error
}

/// Reject a `1.1` execution record against a Stage 3 engine with exit `5`,
/// leaving the record untouched (no silent downgrade).
pub(crate) fn require_execution_mode_for_record(
    mode: &ExecutionMode,
) -> Result<&ExecutionCapability, CommandError> {
    match mode {
        ExecutionMode::Negotiated { capability, .. } => Ok(capability),
        ExecutionMode::Stage3 => Err(operation_unavailable(
            "This recovery record requires an engine advertising job_execution",
        )),
    }
}

/// Persist a brand-new `1.1` record before any POST. Under `CR-CS-01`, a fresh
/// pre-send storage failure exits `6` `storage_error`.
pub(crate) fn persist_fresh_execution_record<'a>(
    profile: &'a Profile,
    record: &PendingExecutionRecord,
) -> Result<ExecutionRecordLease<'a>, CommandError> {
    let records = SubmissionRecords::lock(profile).map_err(fresh_execution_record_error)?;
    records
        .save_new_execution(record)
        .map_err(fresh_execution_record_error)?;
    records
        .coordinate_execution(record)
        .map_err(fresh_execution_record_error)
}

fn fresh_execution_record_error(error: RecordError) -> CommandError {
    match error {
        RecordError::Storage => CommandError::recovery_save_failure(
            RequestAcceptance::NotSent,
            "Protected local storage is unavailable for the pending recovery record",
            serde_json::json!({}),
        ),
        other => super::super::submission::record_error(other),
    }
}

pub(crate) async fn send_execution_record(
    client: &Client,
    capability: &ExecutionCapability,
    record_lease: &ExecutionRecordLease<'_>,
    record: &PendingExecutionRecord,
    recovering: bool,
) -> Result<ExecutionSubmissionSuccess, CommandError> {
    let recovering_unknown = recovering && record.receipt.is_none();
    let receipt = match record.operation.as_str() {
        "jobs.submit" => {
            let body_utf8 = record
                .request_body_utf8
                .as_deref()
                .ok_or_else(|| super::super::submission::record_error(RecordError::Invalid))?;
            let body = ExecutionSubmissionBody::replay(body_utf8.as_bytes().to_vec())
                .map_err(|_| super::super::submission::record_error(RecordError::Invalid))?;
            client
                .submit_execution_job_with(capability, &record.key, &body)
                .await
                .map_err(|error| {
                    execution_send_error(error, &record.sub_id, &record.key, recovering_unknown)
                })?
        }
        "jobs.retry" => {
            let source_job_id = record
                .source_job_id
                .as_ref()
                .ok_or_else(|| super::super::submission::record_error(RecordError::Invalid))?;
            client
                .retry_execution_job_with(capability, source_job_id, &record.key)
                .await
                .map_err(|error| {
                    execution_send_error(error, &record.sub_id, &record.key, recovering_unknown)
                })?
        }
        _ => return Err(super::super::submission::record_error(RecordError::Invalid)),
    };
    save_execution_receipt_or_cr_cs_01(record, &receipt, |rec, acc| {
        record_lease.save_receipt(rec, acc)
    })?;
    Ok(ExecutionSubmissionSuccess {
        sub_id: Some(record.sub_id.clone()),
        receipt,
    })
}

pub(crate) fn save_execution_receipt_or_cr_cs_01(
    record: &PendingExecutionRecord,
    receipt: &ExecutionAcceptance,
    save: impl FnOnce(&PendingExecutionRecord, ExecutionAcceptance) -> Result<(), RecordError>,
) -> Result<(), CommandError> {
    if save(record, receipt.clone()).is_err() {
        let mut data = serde_json::json!({
            "sub_id": record.sub_id,
            "job_id": receipt.job_id,
        });
        if let Some(retry_of) = &receipt.retry_of {
            data["retry_of"] = serde_json::json!(retry_of);
        }
        return Err(CommandError::recovery_save_failure(
            RequestAcceptance::Accepted { operation_id: None },
            "The job was accepted, but its local recovery receipt could not be saved",
            data,
        ));
    }
    Ok(())
}

pub(crate) fn parse_or_generate_key(raw: Option<&str>) -> Result<IdempotencyKey, CommandError> {
    match raw {
        Some(value) => {
            IdempotencyKey::parse(value).map_err(|_| usage_error("Idempotency key is invalid"))
        }
        None => IdempotencyKey::parse(format!("submit-{}", random_hex()?))
            .map_err(|_| usage_error("Could not generate idempotency key")),
    }
}

pub(crate) fn random_hex() -> Result<String, CommandError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CommandError {
        category: "entropy_unavailable",
        message: "Secure random generation is unavailable",
        exit_code: 6,
        context: None,
    })?;
    Ok(super::super::hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_api::{
        ApiError, ApiErrorBody, ClientId, CorrelationId, ErrorCode, ExecutionJobSnapshot,
        InstallationId, JobId, SubmissionClientError, decode_execution_json,
    };

    fn sample_retry_record(receipt: Option<ExecutionAcceptance>) -> PendingExecutionRecord {
        PendingExecutionRecord {
            record_version: "1.1".into(),
            sub_id: SubmissionId::parse("sub_0123456789abcdef0123456789abcdef").expect("sub"),
            installation_id: InstallationId::parse("ins_0123456789abcdef0123456789abcdef")
                .expect("ins"),
            client_id: ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("cli"),
            operation: "jobs.retry".into(),
            key: IdempotencyKey::parse("retry-key-1").expect("key"),
            job_contract: JOB_CONTRACT.into(),
            request_body_utf8: None,
            source_job_id: Some(JobId::parse("job_00000000000000000000000000000001").expect("job")),
            input_identities: Vec::new(),
            receipt,
        }
    }

    fn sample_acceptance() -> ExecutionAcceptance {
        let snap: ExecutionJobSnapshot = decode_execution_json(
            include_bytes!("../../../../api/tests/fixtures/execution-snapshot.json"),
            262_144,
        )
        .expect("fixture snapshot");
        ExecutionAcceptance {
            api_version: "1.0".into(),
            accepted: true,
            job_id: JobId::parse("job_00000000000000000000000000000002").expect("job2"),
            replayed: false,
            acceptance_sequence: 2,
            snapshot_revision: 1,
            resolved: snap.resolved,
            job_contract: JOB_CONTRACT.into(),
            retry_of: Some(JobId::parse("job_00000000000000000000000000000001").expect("job1")),
        }
    }

    #[test]
    fn execution_record_on_stage3_engine_exits_5_and_leaves_record_untouched() {
        let error = require_execution_mode_for_record(&ExecutionMode::Stage3)
            .expect_err("Stage 3 engine must refuse 1.1 record");
        assert_eq!(error.exit_code, 5);
        assert_eq!(error.category, "operation_unavailable");
    }

    #[test]
    fn fresh_execution_record_storage_failure_exits_6_under_cr_cs_01() {
        let error = fresh_execution_record_error(RecordError::Storage);
        assert_eq!(error.exit_code, 6);
        assert_eq!(error.category, "storage_error");
    }

    #[test]
    fn recovery_with_saved_receipt_preserves_accepted_true_and_job_id_on_auth_failure() {
        let acceptance = sample_acceptance();
        let record = sample_retry_record(Some(acceptance.clone()));
        let auth_err = CommandError {
            category: "unauthorized",
            message: "This profile is not authorized",
            exit_code: 4,
            context: None,
        };
        let preserved = preserve_execution_recovery_status(auth_err, &record);
        assert_eq!(preserved.exit_code, 4);
        let ctx = preserved.context.as_deref().expect("context");
        assert_eq!(ctx.accepted, Some(serde_json::Value::Bool(true)));
        let raw = ctx.raw_data.as_deref().expect("raw receipt");
        let parsed: serde_json::Value = serde_json::from_str(raw.get()).expect("valid json");
        assert_eq!(parsed["job_id"], acceptance.job_id.as_str());
        assert_eq!(parsed["sub_id"], record.sub_id.as_str());
    }

    #[test]
    fn recover_receipt_save_failure_preserves_cr_cs_01_for_both_none_and_some_prior_receipt() {
        let acceptance = sample_acceptance();
        for prior in [None, Some(acceptance.clone())] {
            let record = sample_retry_record(prior.clone());
            let err = save_execution_receipt_or_cr_cs_01(&record, &acceptance, |_, _| {
                Err(RecordError::Storage)
            })
            .expect_err("unsaved receipt");
            let final_err = if record.receipt.is_some() {
                preserve_execution_recovery_status(err, &record)
            } else {
                err
            };
            assert_eq!(final_err.exit_code, 19);
            assert_eq!(final_err.category, "recovery_storage_failed");
            let ctx = final_err.context.as_deref().expect("context");
            assert_eq!(ctx.accepted, Some(serde_json::Value::Bool(true)));
            let data = ctx.data.as_ref().expect("data");
            assert_eq!(data["receipt_confirmed"], true);
            assert_eq!(data["pending_record_saved"], false);
            assert_eq!(data["sub_id"], record.sub_id.as_str());
            assert_eq!(data["job_id"], acceptance.job_id.as_str());
        }
    }

    #[test]
    fn unknown_recovery_keeps_accepted_null_on_pre_binding_rejections() {
        let sub_id = SubmissionId::parse("sub_0123456789abcdef0123456789abcdef").expect("sub");
        let key = IdempotencyKey::parse("retry-key-1").expect("key");
        for code in [
            ErrorCode::Unauthorized,
            ErrorCode::CapacityExceeded,
            ErrorCode::StoreUnavailable,
        ] {
            let err = execution_send_error(
                SubmissionClientError::Rejected(Box::new(ApiError {
                    api_version: "1.0".into(),
                    error: ApiErrorBody {
                        code,
                        message: "rejected".into(),
                        correlation_id: CorrelationId::parse(
                            "corr_0123456789abcdef0123456789abcdef",
                        )
                        .expect("corr"),
                        retryable: false,
                        details: None,
                    },
                    operation_id: None,
                })),
                &sub_id,
                &key,
                true,
            );
            assert_eq!(
                err.context.as_deref().and_then(|c| c.accepted.as_ref()),
                Some(&serde_json::Value::Null)
            );
        }
    }
}
