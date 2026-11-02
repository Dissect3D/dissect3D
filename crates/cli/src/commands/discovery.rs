//! Read-only model, runtime and task inspection through the shared API client.

use super::{
    CommandError, CommandErrorContext, data_root, invalid_error, read_unconfigured, tokio_runtime,
};
use crate::args::{ModelsCommand, RuntimesCommand, TasksCommand};
use crate::config::ConfigFile;
use crate::connection::Profile;
use dissect3d_api::{
    Client, ClientError, ClientLimits, ModelListQuery, ModelLookup, PageQuery, RuntimeLookup,
    TaskKey, TaskListQuery, TaskLookup,
};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

pub(crate) struct Success {
    pub(crate) command: &'static str,
    pub(crate) data: Value,
    pub(crate) warnings: Vec<String>,
}

pub(crate) fn models(
    command: ModelsCommand,
    config: &ConfigFile,
    config_path: &Path,
    client_limits: ClientLimits,
) -> Result<Success, CommandError> {
    match command {
        ModelsCommand::List {
            task,
            task_version,
            limit,
            cursor,
        } => connected(config, config_path, client_limits, |client| {
            if task.is_none() && task_version.is_some() {
                return Err(usage_error());
            }
            let page = tokio_runtime()
                .block_on(client.models(ModelListQuery {
                    page: PageQuery { limit, cursor },
                    task_id: task,
                    task_version,
                    loaded: None,
                }))
                .map_err(discovery_error)?;
            success("models list", page)
        }),
        ModelsCommand::Show {
            selector,
            task,
            task_version,
            runtime,
            variant,
        } => connected(config, config_path, client_limits, |client| {
            let task = match (task, task_version) {
                (Some(id), Some(version)) => {
                    Some(TaskKey::new(&id, &version).map_err(|_| usage_error())?)
                }
                (None, None) => None,
                _ => return Err(usage_error()),
            };
            let detail = tokio_runtime()
                .block_on(client.model(ModelLookup {
                    selector,
                    task,
                    runtime_ref: runtime,
                    variant,
                }))
                .map_err(discovery_error)?;
            success("models show", detail)
        }),
        ModelsCommand::Loaded { limit, cursor } => {
            connected(config, config_path, client_limits, |client| {
                let page = tokio_runtime()
                    .block_on(client.models_loaded(PageQuery { limit, cursor }))
                    .map_err(discovery_error)?;
                success("models loaded", page)
            })
        }
    }
}

pub(crate) fn runtimes(
    command: RuntimesCommand,
    config: &ConfigFile,
    config_path: &Path,
    client_limits: ClientLimits,
) -> Result<Success, CommandError> {
    match command {
        RuntimesCommand::List { limit, cursor } => {
            connected(config, config_path, client_limits, |client| {
                let page = tokio_runtime()
                    .block_on(client.runtimes(PageQuery { limit, cursor }))
                    .map_err(discovery_error)?;
                success("runtimes list", page)
            })
        }
        RuntimesCommand::Show { selector } => {
            connected(config, config_path, client_limits, |client| {
                let detail = tokio_runtime()
                    .block_on(client.runtime(RuntimeLookup { selector }))
                    .map_err(discovery_error)?;
                success("runtimes show", detail)
            })
        }
    }
}

pub(crate) fn tasks(
    command: TasksCommand,
    config: &ConfigFile,
    config_path: &Path,
    client_limits: ClientLimits,
) -> Result<Success, CommandError> {
    match command {
        TasksCommand::List {
            support,
            limit,
            cursor,
        } => connected(config, config_path, client_limits, |client| {
            let page = tokio_runtime()
                .block_on(client.tasks(TaskListQuery {
                    page: PageQuery { limit, cursor },
                    support_ref: support,
                }))
                .map_err(discovery_error)?;
            success("tasks list", page)
        }),
        TasksCommand::Show {
            selector,
            task_version,
            support,
        } => connected(config, config_path, client_limits, |client| {
            let detail = tokio_runtime()
                .block_on(client.task(TaskLookup {
                    selector,
                    version: task_version,
                    support_ref: support,
                }))
                .map_err(discovery_error)?;
            success("tasks show", detail)
        }),
    }
}

fn connected<T>(
    config: &ConfigFile,
    config_path: &Path,
    client_limits: ClientLimits,
    action: impl FnOnce(Client) -> Result<T, CommandError>,
) -> Result<T, CommandError> {
    let root = data_root(config, config_path).ok_or_else(read_unconfigured("unavailable"))?;
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let _profile_control = profile.lock_control().map_err(CommandError::connection)?;
    let engine = profile
        .connection(&root, client_limits.connect_timeout, client_limits)
        .map_err(CommandError::connection)?;
    let credential = profile
        .selected_credential(config, &engine)
        .map_err(CommandError::connection)?;
    let client = engine
        .client(credential)
        .map_err(CommandError::connection)?;
    action(client)
}

fn success<T: Serialize>(command: &'static str, value: T) -> Result<Success, CommandError> {
    let data = serde_json::to_value(value).map_err(|_| invalid_error())?;
    let warnings = if contains_unsupported_semantics(&data) {
        vec!["required_feature_unsupported".to_owned()]
    } else {
        Vec::new()
    };
    Ok(Success {
        command,
        data,
        warnings,
    })
}

fn contains_unsupported_semantics(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            object.get("code").and_then(Value::as_str) == Some("required_feature_unsupported")
                || object.values().any(contains_unsupported_semantics)
        }
        Value::Array(values) => values.iter().any(contains_unsupported_semantics),
        _ => false,
    }
}

fn discovery_error(error: ClientError) -> CommandError {
    use dissect3d_api::ErrorCode;
    match error {
        ClientError::Rejected(ErrorCode::NotFound) => {
            failure("not_found", "No matching discovery record was found", 19)
        }
        ClientError::Rejected(ErrorCode::AmbiguousSelection) => failure(
            "ambiguous_selection",
            "The discovery selector matches more than one record",
            19,
        ),
        ClientError::Rejected(ErrorCode::InventoryCursorExpired) => failure(
            "inventory_cursor_expired",
            "The inventory cursor expired; start a fresh listing",
            19,
        ),
        ClientError::Rejected(ErrorCode::InvalidRequest) => {
            failure("invalid_request", "The discovery request is invalid", 2)
        }
        ClientError::Rejected(
            ErrorCode::Unauthorized
            | ErrorCode::Forbidden
            | ErrorCode::OriginDenied
            | ErrorCode::HostDenied,
        ) => failure(
            "unauthorized",
            "The profile is not authorized for discovery",
            4,
        ),
        ClientError::Rejected(ErrorCode::Busy | ErrorCode::EngineRecovering)
        | ClientError::Transport => failure(
            "engine_unavailable",
            "The authenticated engine request failed",
            3,
        ),
        ClientError::Rejected(ErrorCode::RequiredFeatureUnsupported) => failure(
            "required_feature_unsupported",
            "The declaration uses unsupported discovery semantics",
            5,
        ),
        ClientError::Rejected(ErrorCode::OperationUnavailable) => failure(
            "operation_unavailable",
            "This engine does not provide the discovery operation",
            5,
        ),
        ClientError::Rejected(ErrorCode::IncompatibleContract) | ClientError::Incompatible => {
            failure(
                "incompatible_contract",
                "The engine discovery contract is incompatible",
                5,
            )
        }
        ClientError::Rejected(ErrorCode::TransferLimit) | ClientError::TransferLimit => failure(
            "transfer_limit",
            "The discovery response exceeded its bound",
            5,
        ),
        ClientError::InvalidMaterial => usage_error(),
        ClientError::InvalidResponse => failure(
            "invalid_response",
            "The selected engine returned an invalid discovery response",
            5,
        ),
        ClientError::Rejected(_) => {
            failure("engine_error", "The engine rejected the discovery read", 5)
        }
    }
}

fn failure(category: &'static str, message: &'static str, exit_code: i32) -> CommandError {
    CommandError {
        category,
        message,
        exit_code,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(Value::Null),
            ..Default::default()
        })),
    }
}

fn usage_error() -> CommandError {
    CommandError {
        category: "usage_error",
        message: "Invalid discovery selector or option combination",
        exit_code: 2,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(Value::Null),
            ..Default::default()
        })),
    }
}
