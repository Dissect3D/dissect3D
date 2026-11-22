//! `engine start` and `engine stop`: native launch, readiness, shutdown requests
//! and pending-stop receipts. `engine status` and `engine info` stay in the
//! dispatcher.

use super::*;

pub(super) fn start(
    config: &ConfigFile,
    config_path: &Path,
    timeout: Duration,
    client_limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    let deadline = Instant::now() + timeout;
    let root = data_root(config, config_path).ok_or_else(unconfigured)?;
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let initial_probe = timeout.min(client_limits.connect_timeout);
    if let Ok(engine) = profile.connection(&root, initial_probe, client_limits) {
        return Ok(serde_json::json!({
            "installation_id": engine.discovery.installation_id,
            "instance_id": engine.discovery.instance_id,
            "ready": true,
            "already_running": true
        }));
    }
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(CommandError {
            category: "engine_start_unconfirmed",
            message: "Engine startup was not confirmed before the deadline",
            exit_code: 3,
            context: None,
        });
    }
    let binary = engine_binary(config).ok_or_else(unconfigured)?;
    let _launched = launch_engine(&binary, &root).map_err(|error| CommandError {
        category: "engine_start_failed",
        message: if error == dissect3d_platform::PlatformError::LaunchRestricted {
            "The launcher restricts independent engine lifetime; run the installed CLI directly outside its Job Object"
        } else { "The configured engine could not be started" },
        exit_code: 3,
        context: None,
    })?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let engine =
        dissect3d_connection::observe_readiness(remaining, Duration::from_millis(100), |budget| {
            match profile.connection(
                &root,
                budget.min(client_limits.connect_timeout),
                client_limits,
            ) {
                Ok(engine) => Ok(engine),
                Err(ConnectionError::Invalid) => {
                    Err(dissect3d_connection::ReadinessError::InvalidDiscovery)
                }
                Err(ConnectionError::Incompatible) => {
                    Err(dissect3d_connection::ReadinessError::Incompatible)
                }
                Err(_) => Err(dissect3d_connection::ReadinessError::Unavailable),
            }
        })
        .map_err(|error| match error {
            dissect3d_connection::ReadinessError::InvalidDiscovery => CommandError {
                category: "invalid_discovery",
                message: "The protected engine discovery record is invalid",
                exit_code: 5,
                context: None,
            },
            dissect3d_connection::ReadinessError::Incompatible => CommandError {
                category: "incompatible",
                message: "The engine readiness response is incompatible",
                exit_code: 5,
                context: None,
            },
            dissect3d_connection::ReadinessError::Deadline
            | dissect3d_connection::ReadinessError::Unavailable => CommandError {
                category: "engine_start_unconfirmed",
                message: "Engine startup was not confirmed before the deadline",
                exit_code: 3,
                context: None,
            },
        })?;
    Ok(serde_json::json!({
        "installation_id": engine.discovery.installation_id,
        "instance_id": engine.discovery.instance_id,
        "ready": true,
        "process": engine.discovery.process
    }))
}

pub(super) fn stop(
    config: &ConfigFile,
    config_path: &Path,
    observation_timeout: Duration,
    client_limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    let root = data_root(config, config_path).ok_or_else(unconfigured)?;
    let connection_binding = connection_binding(&root);
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let _profile_control = profile.lock_control().map_err(CommandError::connection)?;
    let saved_pending = profile
        .load_pending_stop()
        .map_err(CommandError::connection)?;
    let engine = match profile.connection(&root, client_limits.connect_timeout, client_limits) {
        Ok(engine) => engine,
        Err(error) => {
            if let Some(mut pending) = saved_pending.clone()
                && matches!(pending.state.as_str(), "pending" | "complete")
                && pending.connection_binding.as_deref() == Some(connection_binding.as_str())
                && matches!(
                    process_matches(&ProcessIdentity {
                        pid: pending.pid,
                        start_marker: pending.start_marker.clone(),
                    }),
                    Ok(false)
                )
            {
                pending.state = "complete".to_owned();
                profile
                    .save_pending_stop(&pending)
                    .map_err(|_| pending_stop_storage_error(&pending, true))?;
                return Ok(pending_stop_data(&pending, true));
            }
            if let Some(pending) = saved_pending.as_ref()
                && pending.state == "pending"
            {
                if pending.connection_binding.as_deref() != Some(connection_binding.as_str()) {
                    // Keep the saved receipt bound to its original target. It
                    // must not be presented as the result for another engine.
                    return Err(CommandError::connection(error));
                }
                return Err(pending
                    .receipt
                    .as_ref()
                    .map_or_else(unconfirmed_stop, |receipt| {
                        unconfirmed_stop_with_receipt(
                            receipt.operation_id.as_str().to_owned(),
                            serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
                        )
                    }));
            }
            return Err(preserve_pending_receipt(
                CommandError::connection(error),
                saved_pending.as_ref().filter(|pending| {
                    pending.connection_binding.as_deref() == Some(connection_binding.as_str())
                }),
            ));
        }
    };
    let process = ProcessIdentity {
        pid: engine.discovery.process.pid,
        start_marker: engine.discovery.process.start_marker.clone(),
    };
    let same_target = |pending: &PendingStop| {
        pending.connection_binding.as_deref() == Some(connection_binding.as_str())
            && pending.installation_id == engine.discovery.installation_id
            && pending.instance_id == engine.discovery.instance_id
            && pending.pid == process.pid
            && pending.start_marker == process.start_marker
    };
    let target_pending = saved_pending
        .as_ref()
        .filter(|pending| same_target(pending));
    let credential = profile
        .selected_credential(config, &engine)
        .map_err(|error| {
            preserve_pending_receipt(CommandError::connection(error), target_pending)
        })?;
    if let Some(previous) = saved_pending
        .as_ref()
        .filter(|pending| pending.state == "pending" && !same_target(pending))
        && !matches!(
            process_matches(&ProcessIdentity {
                pid: previous.pid,
                start_marker: previous.start_marker.clone()
            }),
            Ok(false)
        )
    {
        return Err(CommandError {
            category: "pending_control_conflict",
            message: "This profile retains an unresolved stop for another instance; resolve it before stopping a different target",
            exit_code: 19,
            context: None,
        });
    }
    let reusable = target_pending.filter(|pending| pending.state == "pending");
    let key = match reusable {
        Some(pending) => pending.idempotency_key.clone(),
        None => new_stop_key().map_err(|error| preserve_pending_receipt(error, target_pending))?,
    };
    let mut pending = PendingStop {
        installation_id: engine.discovery.installation_id.clone(),
        instance_id: engine.discovery.instance_id.clone(),
        pid: process.pid,
        start_marker: process.start_marker.clone(),
        idempotency_key: key.clone(),
        connection_binding: Some(connection_binding),
        operation_id: reusable.and_then(|pending| pending.operation_id.clone()),
        receipt: reusable.and_then(|pending| pending.receipt.clone()),
        state: "pending".to_owned(),
    };
    // Persist the target and key before sending the mutation request. A retry
    // can then only recover this exact operation for this exact process.
    profile
        .save_pending_stop(&pending)
        .map_err(|_| pending_stop_storage_error(&pending, false))?;
    let process_watcher = ProcessWatcher::new(&process).map_err(|_| {
        pending
            .receipt
            .as_ref()
            .map_or_else(unconfirmed_stop, |receipt| {
                unconfirmed_stop_with_receipt(
                    receipt.operation_id.as_str().to_owned(),
                    serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
                )
            })
    })?;
    let client = engine
        .client(credential)
        .map_err(|error| pending_stop_connection_error(&pending, error))?;
    let receipt = tokio_runtime().block_on(client.shutdown(key));
    let receipt = match receipt {
        Ok(receipt) => receipt,
        Err(error @ dissect3d_api::ClientError::Rejected(_)) => {
            return Err(pending.receipt.as_ref().map_or_else(
                || api_error(error),
                |receipt| {
                    with_known_shutdown_receipt(
                        api_error(error),
                        receipt.operation_id.as_str().to_owned(),
                        serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
                    )
                },
            ));
        }
        Err(error) if matches!(process_watcher.wait(observation_timeout), Ok(true)) => {
            pending.state = "complete".to_owned();
            profile
                .save_pending_stop(&pending)
                .map_err(|_| pending_stop_storage_error(&pending, false))?;
            return shutdown_transport_result(pending, error, true);
        }
        Err(error) => return shutdown_transport_result(pending, error, false),
    };
    if receipt.target.instance_id != pending.instance_id {
        return Err(pending
            .receipt
            .as_ref()
            .map_or_else(invalid_error, |known| {
                with_known_shutdown_receipt(
                    invalid_error(),
                    known.operation_id.as_str().to_owned(),
                    serde_json::to_value(known).unwrap_or(serde_json::Value::Null),
                )
            }));
    }
    let operation_id = receipt.operation_id.as_str().to_owned();
    let operation = serde_json::to_value(&receipt).map_err(|_| invalid_error())?;
    pending.operation_id = Some(receipt.operation_id.clone());
    pending.receipt = Some(receipt);
    profile.save_pending_stop(&pending).map_err(|_| {
        shutdown_receipt_storage_error(operation_id.clone(), operation.clone(), false)
    })?;
    let exited = match process_watcher.wait(observation_timeout) {
        Ok(exited) => exited,
        Err(_) => return Err(unconfirmed_stop_with_receipt(operation_id, operation)),
    };
    if !exited {
        return Err(unconfirmed_stop_with_receipt(operation_id, operation));
    }
    pending.state = "complete".to_owned();
    profile.save_pending_stop(&pending).map_err(|_| {
        shutdown_receipt_storage_error(operation_id.clone(), operation.clone(), true)
    })?;
    Ok(pending_stop_data(&pending, true))
}

pub(super) fn pending_stop_data(
    pending: &PendingStop,
    process_exit_confirmed: bool,
) -> serde_json::Value {
    serde_json::json!({
        "instance_id": pending.instance_id,
        "accepted": pending.receipt.as_ref().map(|_| true),
        "operation_id": pending.operation_id,
        "operation": pending.receipt,
        "process_exit_confirmed": process_exit_confirmed,
        "receipt_confirmed": pending.receipt.is_some()
    })
}

pub(super) fn shutdown_transport_result(
    pending: PendingStop,
    error: dissect3d_api::ClientError,
    process_exit_confirmed: bool,
) -> Result<serde_json::Value, CommandError> {
    if process_exit_confirmed {
        let mut data = pending_stop_data(&pending, true);
        data["request_error"] = serde_json::json!(api_error(error).category);
        return Ok(data);
    }
    Err(pending
        .receipt
        .as_ref()
        .map_or_else(unconfirmed_stop, |receipt| {
            unconfirmed_stop_with_receipt(
                receipt.operation_id.as_str().to_owned(),
                serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
            )
        }))
}

pub(super) fn pending_stop_storage_error(
    pending: &PendingStop,
    process_exit_confirmed: bool,
) -> CommandError {
    match (&pending.operation_id, &pending.receipt) {
        (Some(operation_id), Some(receipt)) => shutdown_receipt_storage_error(
            operation_id.as_str().to_owned(),
            serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
            process_exit_confirmed,
        ),
        _ => CommandError::connection(ConnectionError::Storage),
    }
}

pub(super) fn pending_stop_connection_error(
    pending: &PendingStop,
    error: ConnectionError,
) -> CommandError {
    preserve_pending_receipt(CommandError::connection(error), Some(pending))
}

pub(super) fn preserve_pending_receipt(
    error: CommandError,
    pending: Option<&PendingStop>,
) -> CommandError {
    let Some(receipt) = pending.and_then(|pending| pending.receipt.as_ref()) else {
        return error;
    };
    with_known_shutdown_receipt(
        error,
        receipt.operation_id.as_str().to_owned(),
        serde_json::to_value(receipt).unwrap_or(serde_json::Value::Null),
    )
}

pub(super) fn with_known_shutdown_receipt(
    mut error: CommandError,
    operation_id: String,
    operation: serde_json::Value,
) -> CommandError {
    error.context = Some(Box::new(CommandErrorContext {
        accepted: Some(serde_json::Value::Bool(true)),
        operation_id: Some(operation_id),
        raw_data: None,
        data: Some(serde_json::json!({
            "operation": operation,
            "process_exit_confirmed": false,
            "pending_record_saved": true
        })),
    }));
    error
}

pub(super) fn shutdown_receipt_storage_error(
    operation_id: String,
    operation: serde_json::Value,
    process_exit_confirmed: bool,
) -> CommandError {
    CommandError {
        category: "storage_error",
        message: "Shutdown was accepted, but its recovery record could not be updated",
        exit_code: 6,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(true)),
            operation_id: Some(operation_id),
            raw_data: None,
            data: Some(serde_json::json!({
                "operation": operation,
                "process_exit_confirmed": process_exit_confirmed,
                "pending_record_saved": false
            })),
        })),
    }
}

pub(super) fn new_stop_key() -> Result<IdempotencyKey, CommandError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| CommandError {
        category: "entropy_unavailable",
        message: "Secure operation identity generation is unavailable",
        exit_code: 6,
        context: None,
    })?;
    let mut key = String::with_capacity(36);
    key.push_str("key_");
    key.push_str(&hex(&bytes));
    bytes.fill(0);
    IdempotencyKey::parse(key).map_err(|_| invalid_error())
}
