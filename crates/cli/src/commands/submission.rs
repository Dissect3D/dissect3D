//! Shared client definition, durable pending records and submission/recovery.

mod control;
use control::SubmissionControl;

use crate::args::JobDefinitionArgs;
use dissect3d_api::{
    InputId, InputRef, JobRequest, SubmissionValue, SubmittedTask, decode_submission_json,
    encode_job_request,
};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_DEFINITION_BYTES: usize = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DefinitionError;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalInput {
    path: PathBuf,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalDefinition {
    cli_request_version: String,
    model: String,
    #[serde(default)]
    task: Option<SubmittedTask>,
    #[serde(default)]
    runtime: Option<String>,
    #[serde(default)]
    variant: Option<String>,
    inputs: BTreeMap<String, Vec<LocalInput>>,
    parameters: BTreeMap<String, SubmissionValue>,
    required_features: Vec<String>,
    evaluation_consent: bool,
}

pub(crate) struct OpenInput {
    role: String,
    file: std::fs::File,
    length: u64,
    media_type: &'static str,
}

impl LocalDefinition {
    fn decode(bytes: &[u8], base: &Path) -> Result<Self, DefinitionError> {
        // The typed decoder alone would accept explicit null for optional fields.
        let fields: BTreeMap<String, SubmissionValue> =
            decode_submission_json(bytes, MAX_DEFINITION_BYTES).map_err(|_| DefinitionError)?;
        for optional in ["task", "runtime", "variant"] {
            if matches!(fields.get(optional), Some(SubmissionValue::Null)) {
                return Err(DefinitionError);
            }
        }
        let mut definition: Self =
            decode_submission_json(bytes, MAX_DEFINITION_BYTES).map_err(|_| DefinitionError)?;
        definition.validate_and_resolve_paths(base)?;
        Ok(definition)
    }

    pub(crate) fn from_args(args: JobDefinitionArgs, cwd: &Path) -> Result<Self, DefinitionError> {
        if let Some(path) = args.request {
            let path = cwd.join(path);
            let file = dissect3d_platform::open_regular_file(&path).map_err(|_| DefinitionError)?;
            let mut bytes = Vec::new();
            file.take(MAX_DEFINITION_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| DefinitionError)?;
            return Self::decode(&bytes, path.parent().ok_or(DefinitionError)?);
        }
        let mut inputs: BTreeMap<String, Vec<LocalInput>> = BTreeMap::new();
        for input in args.input {
            let (role, path) = input.split_once('=').ok_or(DefinitionError)?;
            inputs
                .entry(role.into())
                .or_default()
                .push(LocalInput { path: path.into() });
        }
        let task = match (args.task, args.task_version) {
            (Some(id), Some(version)) => Some(SubmittedTask { id, version }),
            (None, None) => None,
            _ => return Err(DefinitionError),
        };
        let parameters = match args.parameters_json {
            Some(text) => decode_submission_json(text.as_bytes(), MAX_DEFINITION_BYTES)
                .map_err(|_| DefinitionError)?,
            None => BTreeMap::new(),
        };
        let mut definition = Self {
            cli_request_version: "1.0".into(),
            model: args.model.ok_or(DefinitionError)?,
            task,
            runtime: args.runtime,
            variant: args.variant,
            inputs,
            parameters,
            required_features: Vec::new(),
            evaluation_consent: false,
        };
        definition.validate_and_resolve_paths(cwd)?;
        Ok(definition)
    }

    fn validate_and_resolve_paths(&mut self, base: &Path) -> Result<(), DefinitionError> {
        if self.cli_request_version != "1.0" || !base.is_absolute() {
            return Err(DefinitionError);
        }
        self.validate_selected_task(self.task.clone().unwrap_or(SubmittedTask {
            id: "omitted".into(),
            version: "1.0".into(),
        }))?;
        for input in self.inputs.values_mut().flatten() {
            let text = input.path.to_str().ok_or(DefinitionError)?;
            if text.is_empty() || text.chars().count() > 32768 || text.contains('\0') {
                return Err(DefinitionError);
            }
            input.path = base.join(&input.path);
        }
        Ok(())
    }

    fn validate_selected_task(&self, task: SubmittedTask) -> Result<(), DefinitionError> {
        let placeholder = InputId::parse(format!("inp_{}", "0".repeat(32))).unwrap();
        let request = self.request(
            task,
            self.inputs
                .iter()
                .map(|(role, inputs)| {
                    (
                        role.clone(),
                        inputs
                            .iter()
                            .map(|_| InputRef {
                                input_id: placeholder.clone(),
                            })
                            .collect(),
                    )
                })
                .collect(),
        );
        encode_job_request(&request).map_err(|_| DefinitionError)?;
        Ok(())
    }

    fn request(&self, task: SubmittedTask, inputs: BTreeMap<String, Vec<InputRef>>) -> JobRequest {
        JobRequest {
            api_version: "1.0".into(),
            support_ref: self.model.clone(),
            task,
            runtime_ref: self.runtime.clone(),
            variant: self.variant.clone(),
            inputs,
            parameters: self.parameters.clone(),
            required_features: self.required_features.clone(),
            evaluation_consent: self.evaluation_consent,
        }
    }

    fn select_task(&self, declared: &[SubmittedTask]) -> Result<SubmittedTask, DefinitionError> {
        if let Some(task) = &self.task {
            return Ok(task.clone());
        }
        match declared {
            [task] => Ok(task.clone()),
            _ => Err(DefinitionError),
        }
    }

    fn open_inputs(&self) -> Result<Vec<OpenInput>, DefinitionError> {
        let mut opened = Vec::new();
        let mut total = 0u64;
        for (role, inputs) in &self.inputs {
            for input in inputs {
                let file = dissect3d_platform::open_regular_file(&input.path)
                    .map_err(|_| DefinitionError)?;
                let length = file.metadata().map_err(|_| DefinitionError)?.len();
                total = total.checked_add(length).ok_or(DefinitionError)?;
                if !(1..=268_435_456).contains(&length) || total > 1_073_741_824 {
                    return Err(DefinitionError);
                }
                // The Stage 3 capture contract uses binary transport; task
                // validation, rather than a filename suffix, establishes format.
                let media_type = "application/octet-stream";
                opened.push(OpenInput {
                    role: role.clone(),
                    file,
                    length,
                    media_type,
                });
            }
        }
        Ok(opened)
    }
}

async fn submit_inner(
    args: JobDefinitionArgs,
    config: &crate::config::ConfigFile,
    config_path: &Path,
    limits: dissect3d_api::ClientLimits,
    control: &SubmissionControl,
) -> Result<serde_json::Value, super::CommandError> {
    use crate::submissions::{PendingSubmission, SubmissionRecords};
    use dissect3d_api::{IdempotencyKey, ModelLookup, PageQuery, SubmissionId, TaskListQuery};

    let key = match args.idempotency_key.as_deref() {
        Some(value) => IdempotencyKey::parse(value).map_err(|_| definition_error())?,
        None => IdempotencyKey::parse(format!("submit-{}", random_hex()?))
            .map_err(|_| definition_error())?,
    };
    let cwd = std::env::current_dir().map_err(|_| definition_error())?;
    let definition = LocalDefinition::from_args(args, &cwd).map_err(|_| definition_error())?;
    let root = super::data_root(config, config_path).ok_or_else(|| {
        failure(
            "engine_unavailable",
            "Configure an engine connection before submitting",
            3,
            Some(false),
            None,
        )
    })?;
    let profile = crate::connection::Profile::open(config_path).map_err(before_connection_error)?;
    let records = SubmissionRecords::lock(&profile).map_err(record_error)?;
    let engine = profile
        .connection(&root, limits.connect_timeout, limits)
        .map_err(before_connection_error)?;
    let credential = profile
        .selected_credential(config, &engine)
        .map_err(before_connection_error)?;
    let installation_id = credential.installation_id.clone();
    let client_id = credential.client_id.clone();
    let client = engine.client(credential).map_err(before_connection_error)?;
    {
        control.checkpoint().await?;
        let info = client.info().await.map_err(before_client_error)?;
        require_operations(&info)?;
        let declared = if definition.task.is_none() {
            let model = client
                .model(ModelLookup {
                    selector: definition.model.clone(),
                    runtime_ref: definition.runtime.clone(),
                    variant: definition.variant.clone(),
                    ..Default::default()
                })
                .await
                .map_err(before_client_error)?;
            let tasks = client
                .tasks(TaskListQuery {
                    page: PageQuery {
                        limit: Some(2),
                        cursor: None,
                    },
                    support_ref: Some(model.item.summary.support_ref),
                })
                .await
                .map_err(before_client_error)?;
            if tasks.next_cursor.is_some() {
                return Err(definition_error());
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
        let task = definition
            .select_task(&declared)
            .map_err(|_| definition_error())?;
        definition
            .validate_selected_task(task.clone())
            .map_err(|_| definition_error())?;
        // Open and validate every selected regular file before the first upload.
        let inputs = definition.open_inputs().map_err(|_| definition_error())?;
        let mut references: BTreeMap<String, Vec<InputRef>> = BTreeMap::new();
        let mut identities = Vec::new();
        for input in inputs {
            control.checkpoint().await?;
            let receipt = client
                .create_input(
                    tokio::fs::File::from_std(input.file),
                    input.length,
                    input.media_type,
                )
                .await
                .map_err(before_client_error)?;
            references.entry(input.role).or_default().push(InputRef {
                input_id: receipt.identity.input_id.clone(),
            });
            identities.push(receipt.identity);
        }
        let request = definition.request(task, references);
        let body = encode_job_request(&request).map_err(|_| definition_error())?;
        let record = PendingSubmission {
            record_version: "1.0".into(),
            sub_id: SubmissionId::parse(format!("sub_{}", random_hex()?))
                .map_err(|_| definition_error())?,
            installation_id,
            client_id,
            operation: "jobs.submit".into(),
            key,
            request_body_utf8: String::from_utf8(body).map_err(|_| definition_error())?,
            input_identities: identities,
            receipt: None,
        };
        control.local_id(record.sub_id.clone());
        control.checkpoint().await?;
        records.save_new(&record).map_err(record_error)?;
        send_record(&client, &records, &record, control).await
    }
}

pub(crate) fn submit(
    args: JobDefinitionArgs,
    config: &crate::config::ConfigFile,
    path: &Path,
    limits: dissect3d_api::ClientLimits,
) -> Result<serde_json::Value, super::CommandError> {
    let runtime = super::tokio_runtime();
    let (control, signal) = SubmissionControl::new(&runtime)?;
    runtime.block_on(control.run(signal, submit_inner(args, config, path, limits, &control)))
}

pub(crate) fn recover(
    id: &str,
    config: &crate::config::ConfigFile,
    path: &Path,
    limits: dissect3d_api::ClientLimits,
) -> Result<serde_json::Value, super::CommandError> {
    use crate::submissions::SubmissionRecords;
    let runtime = super::tokio_runtime();
    let (control, signal) = SubmissionControl::new(&runtime)?;
    runtime.block_on(control.run(signal,async {
        let id=dissect3d_api::SubmissionId::parse(id).map_err(|_|definition_error())?;
        let profile=SubmissionRecords::open_existing(path).map_err(record_error)?;
        let records=SubmissionRecords::lock(&profile).map_err(record_error)?;
        let record=records.load(&id).map_err(record_error)?;
        control.local_id(id);
        if let Some(receipt)=&record.receipt {control.accepted(receipt.clone());}
        use std::io::Write;
        let _=writeln!(std::io::stderr().lock(),"Explicit recovery may FIRST accept a job; it repeats the stored request and key without reading or uploading source files.");
        let root=super::data_root(config,path).ok_or_else(||failure("engine_unavailable","Configure the original engine connection before recovery",3,Some(false),None))?;
        let engine=profile.connection(&root,limits.connect_timeout,limits).map_err(before_connection_error)?;
        let credential=profile.selected_credential(config,&engine).map_err(before_connection_error)?;
        if credential.installation_id!=record.installation_id || credential.client_id!=record.client_id {
            return Err(failure("recovery_identity_mismatch","Recovery requires the original installation and credential",5,Some(false),None));
        }
        let client=engine.client(credential).map_err(before_connection_error)?;
        send_record(&client,&records,&record,&control).await
    }))
}

async fn send_record(
    client: &dissect3d_api::Client,
    records: &crate::submissions::SubmissionRecords<'_>,
    record: &crate::submissions::PendingSubmission,
    control: &SubmissionControl,
) -> Result<serde_json::Value, super::CommandError> {
    let request = dissect3d_api::decode_job_request(record.request_body_utf8.as_bytes())
        .map_err(|_| record_error(crate::submissions::RecordError::Invalid))?;
    let receipt = match client
        .submit_job_observed(&record.key, &request, || control.begin_send())
        .await
    {
        Ok(receipt) => receipt,
        Err(dissect3d_api::SubmissionClientError::CancelledBeforeSend) => {
            return control.interrupt_outcome();
        }
        Err(error) => {
            if matches!(&error, dissect3d_api::SubmissionClientError::Rejected(_)) {
                control.rejected();
            }
            return Err(send_error(error, &record.sub_id));
        }
    };
    control.accepted(receipt.clone());
    let data = serde_json::json!({"accepted":true,"sub_id":record.sub_id,"job_id":receipt.job_id,"replayed":receipt.replayed});
    if records.save_receipt(record, receipt).is_err() {
        return Err(failure(
            "recovery_storage_failed",
            "The job was accepted, but its local receipt could not be saved",
            19,
            Some(true),
            Some(data),
        ));
    }
    Ok(data)
}

fn random_hex() -> Result<String, super::CommandError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| definition_error())?;
    Ok(super::hex(&bytes))
}

fn require_operations(info: &dissect3d_api::EngineInfo) -> Result<(), super::CommandError> {
    let Some(capability) = &info.submission else {
        return Err(failure(
            "operation_unavailable",
            "Durable submission is unavailable on this engine",
            5,
            Some(false),
            None,
        ));
    };
    if capability.version != "1.0" || capability.dispatch_enabled {
        return Err(failure(
            "incompatible",
            "The engine submission capability is incompatible",
            5,
            Some(false),
            None,
        ));
    }
    for operation in ["inputs.create", "jobs.submit"] {
        if !capability.operations.iter().any(|value| value == operation) {
            return Err(failure(
                "operation_unavailable",
                "Durable submission is unavailable on this engine",
                5,
                Some(false),
                None,
            ));
        }
        if !info
            .granted_operations
            .iter()
            .any(|value| value == operation)
        {
            return Err(failure(
                "unauthorized",
                "This credential lacks submission access",
                4,
                Some(false),
                None,
            ));
        }
    }
    Ok(())
}

pub(crate) fn record_error(error: crate::submissions::RecordError) -> super::CommandError {
    use crate::submissions::RecordError;
    let (category, message) = match error {
        RecordError::Missing => (
            "recovery_record_unavailable",
            "No local recovery record exists for this submission ID",
        ),
        RecordError::Invalid => (
            "recovery_record_invalid",
            "The local recovery record is malformed or inconsistent",
        ),
        RecordError::Capacity => (
            "local_capacity_rejected",
            "The protected recovery record budget is exhausted",
        ),
        RecordError::Storage => (
            "local_storage_unavailable",
            "Protected recovery storage is unavailable",
        ),
        RecordError::Busy => (
            "profile_busy",
            "The selected profile is busy; retry the command",
        ),
    };
    failure(category, message, 2, Some(false), None)
}

fn definition_error() -> super::CommandError {
    failure(
        "usage_error",
        "The local job definition, task choice or selected input is invalid",
        2,
        Some(false),
        None,
    )
}

fn before_connection_error(error: crate::connection::ConnectionError) -> super::CommandError {
    let mut error = super::CommandError::connection(error);
    error.context.get_or_insert_with(Default::default).accepted =
        Some(serde_json::Value::Bool(false));
    error
}

pub(super) fn before_client_error(error: dissect3d_api::ClientError) -> super::CommandError {
    if let dissect3d_api::ClientError::Rejected(code) = error {
        return rejected_error(code, None);
    }
    let mut error = super::api_error(error);
    error.context.get_or_insert_with(Default::default).accepted =
        Some(serde_json::Value::Bool(false));
    error
}

fn send_error(
    error: dissect3d_api::SubmissionClientError,
    id: &dissect3d_api::SubmissionId,
) -> super::CommandError {
    use dissect3d_api::SubmissionClientError;
    let (mut result, correlation_id) = match error {
        SubmissionClientError::BeforeSend(error) => (before_client_error(error), None),
        SubmissionClientError::CancelledBeforeSend => (
            failure(
                "interrupted_not_submitted",
                "Interrupted before submitting a job",
                18,
                Some(false),
                None,
            ),
            None,
        ),
        SubmissionClientError::Uncertain { correlation_id } => (
            failure(
                "submission_uncertain",
                "Submission may have been accepted; use explicit jobs recover with this submission ID",
                15,
                None,
                None,
            ),
            correlation_id,
        ),
        SubmissionClientError::Rejected(error) => (
            rejected_error(error.error.code, Some(id)),
            Some(error.error.correlation_id),
        ),
    };
    result.context.get_or_insert_with(Default::default).data = Some(serde_json::json!({
        "sub_id": id, "correlation_id": correlation_id,
    }));
    result
}

fn failure(
    category: &'static str,
    message: &'static str,
    exit_code: i32,
    accepted: Option<bool>,
    data: Option<serde_json::Value>,
) -> super::CommandError {
    super::CommandError {
        category,
        message,
        exit_code,
        context: Some(Box::new(super::CommandErrorContext {
            accepted: accepted.map(serde_json::Value::Bool),
            data,
            operation_id: None,
        })),
    }
}

fn rejected_error(
    code: dissect3d_api::ErrorCode,
    id: Option<&dissect3d_api::SubmissionId>,
) -> super::CommandError {
    use dissect3d_api::ErrorCode;
    let category = match code {
        ErrorCode::Unauthorized => "unauthorized",
        ErrorCode::Forbidden => "forbidden",
        ErrorCode::OriginDenied => "origin_denied",
        ErrorCode::HostDenied => "host_denied",
        ErrorCode::InvalidRequest => "invalid_request",
        ErrorCode::IdempotencyConflict => "idempotency_conflict",
        ErrorCode::StoreIncompatible => "store_incompatible",
        ErrorCode::TransferLimit => "transfer_limit",
        ErrorCode::EngineRecovering => "engine_recovering",
        ErrorCode::PersistenceUnavailable => "persistence_unavailable",
        ErrorCode::StorageUnavailable => "storage_unavailable",
        ErrorCode::RequiredFeatureUnsupported => "required_feature_unsupported",
        ErrorCode::IncompatibleContract => "incompatible_contract",
        ErrorCode::OperationUnavailable => "operation_unavailable",
        ErrorCode::NotFound => "not_found",
        ErrorCode::AmbiguousSelection => "ambiguous_selection",
        ErrorCode::InventoryCursorExpired => "inventory_cursor_expired",
        ErrorCode::Busy => "busy",
        ErrorCode::InputUnavailable => "input_unavailable",
        ErrorCode::NotPrepared => "not_prepared",
        ErrorCode::IncompatibleProfile => "incompatible_profile",
        ErrorCode::JobCursorExpired => "job_cursor_expired",
        ErrorCode::DataDeleted => "data_deleted",
        ErrorCode::LengthRequired => "length_required",
        ErrorCode::PayloadTooLarge => "payload_too_large",
        ErrorCode::UnsupportedMediaType => "unsupported_media_type",
        ErrorCode::InvalidInput => "invalid_input",
        ErrorCode::UnsupportedParameter => "unsupported_parameter",
        ErrorCode::CapacityExceeded => "capacity_exceeded",
        ErrorCode::EngineStopping => "engine_stopping",
        ErrorCode::StoreUnavailable => "store_unavailable",
        ErrorCode::StorageIntegrityFault => "storage_integrity_fault",
    };
    let exit = match code {
        ErrorCode::Unauthorized
        | ErrorCode::Forbidden
        | ErrorCode::HostDenied
        | ErrorCode::OriginDenied => 4,
        ErrorCode::OperationUnavailable | ErrorCode::IncompatibleContract => 5,
        ErrorCode::NotPrepared => 6,
        ErrorCode::Busy
        | ErrorCode::CapacityExceeded
        | ErrorCode::StorageUnavailable
        | ErrorCode::StoreUnavailable
        | ErrorCode::PersistenceUnavailable => 7,
        _ => 19,
    };
    failure(
        category,
        "The engine rejected this submission",
        exit,
        Some(false),
        id.map(|id| serde_json::json!({"sub_id": id})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::{Cli, Command, JobsCommand};
    use clap::Parser;

    fn arguments(values: &[&str]) -> crate::args::JobDefinitionArgs {
        let cli = Cli::try_parse_from(values).unwrap();
        match cli.command.unwrap() {
            Command::Jobs {
                command: JobsCommand::Submit(args),
            } => args,
            Command::Run(args) => args.definition,
            _ => panic!("submission arguments"),
        }
    }

    #[test]
    fn argument_and_file_definitions_preserve_decimal_tokens_and_path_bases() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("request.json");
        std::fs::write(&file, br#"{"cli_request_version":"1.0","model":"test.mesh-copy@fixture-r1","task":{"id":"mesh.copy","version":"1.0"},"inputs":{"mesh":[{"path":"shape.obj"}]},"parameters":{"scale":1.000000000000000000000000001},"required_features":[],"evaluation_consent":false}"#).unwrap();
        let definition = LocalDefinition::from_args(
            arguments(&[
                "dissect3d",
                "jobs",
                "submit",
                "--request",
                file.to_str().unwrap(),
            ]),
            temp.path(),
        )
        .unwrap();
        let direct = LocalDefinition::from_args(
            arguments(&[
                "dissect3d",
                "run",
                "--detach",
                "--model",
                "test.mesh-copy@fixture-r1",
                "--task",
                "mesh.copy",
                "--task-version",
                "1.0",
                "--input",
                "mesh=shape.obj",
                "--parameters-json",
                r#"{"scale":1.000000000000000000000000001}"#,
            ]),
            temp.path(),
        )
        .unwrap();
        assert_eq!(definition, direct);
        assert_eq!(
            definition.inputs["mesh"][0].path,
            temp.path().join("shape.obj")
        );
        let text = serde_json::to_string(&definition.parameters).unwrap();
        assert!(text.contains("1.000000000000000000000000001"));
    }

    #[test]
    fn local_definition_rejects_unknown_duplicate_null_and_out_of_budget_values() {
        let valid = r#"{"cli_request_version":"1.0","model":"x","inputs":{"mesh":[{"path":"a.obj"}]},"parameters":{},"required_features":[],"evaluation_consent":false}"#;
        let base = std::env::current_dir().unwrap();
        assert!(LocalDefinition::decode(valid.as_bytes(), &base).is_ok());
        for invalid in [
            valid.replace("\"model\":\"x\"", "\"model\":\"x\",\"model\":\"y\""),
            valid.replace("\"model\":\"x\"", "\"model\":null"),
            valid.replace(
                "\"path\":\"a.obj\"",
                "\"path\":\"a.obj\",\"media_type\":\"model/obj\"",
            ),
            valid.replace("\"parameters\":{}", "\"parameters\":{\"x\":1,\"x\":2}"),
            valid.replace(
                "\"required_features\":[]",
                "\"required_features\":[\"x\",\"x\"]",
            ),
            valid.replace(
                "\"evaluation_consent\":false",
                "\"evaluation_consent\":null",
            ),
            valid.replace(
                "\"inputs\":{\"mesh\":[{\"path\":\"a.obj\"}]}",
                "\"inputs\":{}",
            ),
            valid.replace(
                "\"model\":\"x\"",
                &format!("\"model\":\"{}\"", "x".repeat(1025)),
            ),
        ] {
            assert!(
                LocalDefinition::decode(invalid.as_bytes(), &base).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn omission_requires_one_publicly_declared_task_and_inputs_are_not_opened_early() {
        let base = std::env::current_dir().unwrap();
        let definition = LocalDefinition::from_args(
            arguments(&[
                "dissect3d",
                "jobs",
                "submit",
                "--model",
                "x",
                "--input",
                "mesh=absent.obj",
            ]),
            &base,
        )
        .unwrap();
        let task = dissect3d_api::SubmittedTask {
            id: "mesh.copy".into(),
            version: "1.0".into(),
        };
        assert!(definition.select_task(&[]).is_err());
        assert!(
            definition
                .select_task(&[task.clone(), task.clone()])
                .is_err()
        );
        assert_eq!(
            definition.select_task(std::slice::from_ref(&task)).unwrap(),
            task
        );
        assert!(definition.open_inputs().is_err());
    }

    #[test]
    fn resolved_task_is_validated_against_wire_budget_before_upload() {
        let base = std::env::current_dir().unwrap();
        let parameters = format!(r#"{{"padding":"{}"}}"#, "a".repeat(65_536 - 270));
        let definition = LocalDefinition::from_args(
            arguments(&[
                "dissect3d",
                "jobs",
                "submit",
                "--model",
                "x",
                "--input",
                "mesh=absent.obj",
                "--parameters-json",
                &parameters,
            ]),
            &base,
        )
        .unwrap();
        let task = SubmittedTask {
            id: "t".repeat(128),
            version: "1.0".into(),
        };
        assert!(definition.validate_selected_task(task).is_err());
    }
}
