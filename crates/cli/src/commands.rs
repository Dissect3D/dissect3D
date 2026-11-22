//! Connected commands. Filesystem, discovery, and transport decisions live in
//! the connection layer; handlers return only bounded public data.

pub(crate) mod discovery;
pub(crate) mod jobs;
pub(crate) mod submission;

use crate::args::{AuthCommand, EngineCommand};
use crate::config::ConfigFile;
use crate::connection::{
    ConnectionError, PendingStop, Profile, ProfileCredential, connection_binding,
};
use dissect3d_api::{ClientId, ClientLimits, EnrollmentId, IdempotencyKey};
use dissect3d_platform::{ProcessIdentity, ProcessWatcher, launch_engine, process_matches};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod auth;
mod engine;
use auth::*;
use engine::*;

pub(crate) struct CommandError {
    pub(crate) category: &'static str,
    pub(crate) message: &'static str,
    pub(crate) exit_code: i32,
    pub(crate) context: Option<Box<CommandErrorContext>>,
}

#[derive(Default)]
pub(crate) struct CommandErrorContext {
    pub(crate) accepted: Option<serde_json::Value>,
    pub(crate) operation_id: Option<String>,
    pub(crate) data: Option<serde_json::Value>,
    pub(crate) raw_data: Option<Box<serde_json::value::RawValue>>,
}

impl CommandError {
    fn connection(error: ConnectionError) -> Self {
        match error {
            ConnectionError::Unavailable => Self {
                category: "engine_unavailable",
                message: "The selected engine is unavailable",
                exit_code: 3,
                context: Some(Box::new(CommandErrorContext {
                    accepted: None,
                    operation_id: None,
                    raw_data: None,
                    data: Some(serde_json::json!({
                    "status": "unavailable",
                    "detail": "engine_unavailable"
                    })),
                })),
            },
            ConnectionError::Unauthorized => Self {
                category: "unauthorized",
                message: "This profile is not authorized for the selected engine",
                exit_code: 4,
                context: None,
            },
            ConnectionError::Incompatible => Self {
                category: "incompatible",
                message: "The selected engine does not match this profile or CLI",
                exit_code: 5,
                context: None,
            },
            ConnectionError::Storage => Self {
                category: "storage_error",
                message: "Protected profile storage is unavailable",
                exit_code: 6,
                context: None,
            },
            ConnectionError::ProfileBusy => Self {
                category: "profile_busy",
                message: "Another command is updating this profile; retry after it completes",
                exit_code: 7,
                context: None,
            },
            ConnectionError::Capacity => Self {
                category: "capacity_rejected",
                message: "The engine enrollment limit was reached",
                exit_code: 7,
                context: None,
            },
            ConnectionError::Conflict => Self {
                category: "enrollment_conflict",
                message: "The retained enrollment conflicts with an existing binding",
                exit_code: 19,
                context: None,
            },
            ConnectionError::EnrollmentRejected => Self {
                category: "usage_error",
                message: "The engine rejected the enrollment request",
                exit_code: 2,
                context: None,
            },
            ConnectionError::Invalid => Self {
                category: "invalid_response",
                message: "The selected engine or profile data is invalid",
                exit_code: 5,
                context: None,
            },
        }
    }
}

pub(crate) fn engine(
    command: EngineCommand,
    config: &ConfigFile,
    config_path: &Path,
    start_timeout_ms: u64,
    stop_timeout_ms: u64,
    client_limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    match command {
        EngineCommand::Start => start(
            config,
            config_path,
            Duration::from_millis(start_timeout_ms),
            client_limits,
        ),
        EngineCommand::Status => {
            let root =
                data_root(config, config_path).ok_or_else(read_unconfigured("unavailable"))?;
            let profile = Profile::open(config_path).map_err(CommandError::connection)?;
            let engine = profile
                .connection(&root, client_limits.connect_timeout, client_limits)
                .map_err(CommandError::connection)?;
            let credential = profile
                .credential_snapshot(config, &engine)
                .map_err(CommandError::connection)?;
            let client = engine
                .client(credential)
                .map_err(CommandError::connection)?;
            let info = tokio_runtime().block_on(client.info()).map_err(api_error)?;
            Ok(serde_json::json!({
                "installation_id": engine.discovery.installation_id,
                "instance_id": engine.discovery.instance_id,
                "ready": matches!(info.phase, dissect3d_api::EnginePhase::Ready)
            }))
        }
        EngineCommand::Info => {
            let root =
                data_root(config, config_path).ok_or_else(read_unconfigured("unavailable"))?;
            let profile = Profile::open(config_path).map_err(CommandError::connection)?;
            let engine = profile
                .connection(&root, client_limits.connect_timeout, client_limits)
                .map_err(CommandError::connection)?;
            let credential = profile
                .credential_snapshot(config, &engine)
                .map_err(CommandError::connection)?;
            let client = engine
                .client(credential)
                .map_err(CommandError::connection)?;
            let info = tokio_runtime().block_on(client.info()).map_err(api_error)?;
            serde_json::to_value(info).map_err(|_| invalid_error())
        }
        EngineCommand::Stop => stop(
            config,
            config_path,
            Duration::from_millis(stop_timeout_ms),
            client_limits,
        ),
    }
}

pub(crate) fn auth(
    command: AuthCommand,
    config: &ConfigFile,
    config_path: &Path,
    client_limits: ClientLimits,
) -> Result<serde_json::Value, CommandError> {
    let root = data_root(config, config_path).ok_or_else(|| match command {
        AuthCommand::Status => read_unconfigured("unverified")(),
        AuthCommand::Setup { .. } | AuthCommand::Revoke => unconfigured(),
    })?;
    let profile = Profile::open(config_path).map_err(CommandError::connection)?;
    let _profile_control = profile.lock_control().map_err(CommandError::connection)?;
    if matches!(
        command,
        AuthCommand::Setup {
            submission_access: true
        }
    ) {
        if config
            .explicit_credential_reference()
            .map_err(|_| invalid_error())?
            .is_some()
        {
            return Err(CommandError {
                category: "usage_error",
                message: "Clear the explicit credential reference before enrollment setup",
                exit_code: 2,
                context: None,
            });
        }
        let pending_replay = profile
            .load()
            .map_err(CommandError::connection)?
            .is_some_and(|credential| {
                credential.state == "pending" && credential.submission_access
            })
            && profile
                .load_pending_stop()
                .map_err(CommandError::connection)?
                .is_none();
        if !pending_replay
            && profile
                .has_saved_records()
                .map_err(CommandError::connection)?
        {
            return Err(submission_access_requires_new_profile());
        }
    }
    let engine = match profile.connection(&root, client_limits.connect_timeout, client_limits) {
        Ok(engine) => engine,
        Err(ConnectionError::Unavailable) if matches!(&command, AuthCommand::Status) => {
            return Err(unverified_connection());
        }
        Err(error) => return Err(CommandError::connection(error)),
    };
    match command {
        AuthCommand::Setup { submission_access } => {
            if submission_access
                && profile
                    .load()
                    .map_err(CommandError::connection)?
                    .is_some_and(|credential| {
                        credential.installation_id != engine.discovery.installation_id
                    })
            {
                return Err(submission_access_requires_new_profile());
            }
            if config
                .explicit_credential_reference()
                .map_err(|_| invalid_error())?
                .is_some()
            {
                return Err(CommandError {
                    category: "usage_error",
                    message: "Clear the explicit credential reference before enrollment setup",
                    exit_code: 2,
                    context: None,
                });
            }
            setup(&profile, &engine, submission_access)
        }
        AuthCommand::Status => {
            let credential = profile
                .selected_credential(config, &engine)
                .map_err(CommandError::connection)?;
            let client = engine
                .client(credential)
                .map_err(CommandError::connection)?;
            let status = tokio_runtime()
                .block_on(client.auth_status())
                .map_err(api_error)?;
            serde_json::to_value(status).map_err(|_| invalid_error())
        }
        AuthCommand::Revoke => {
            if config
                .explicit_credential_reference()
                .map_err(|_| invalid_error())?
                .is_some()
            {
                let credential = profile
                    .selected_credential(config, &engine)
                    .map_err(CommandError::connection)?;
                let client = engine
                    .client(credential)
                    .map_err(CommandError::connection)?;
                let receipt = match tokio_runtime().block_on(client.revoke_self()) {
                    Ok(receipt) => receipt,
                    Err(error) => return Err(revocation_error(error)),
                };
                return serde_json::to_value(receipt).map_err(|_| invalid_error());
            }
            let mut credential = profile
                .load()
                .map_err(CommandError::connection)?
                .ok_or_else(unauthorized)?;
            if credential.installation_id != engine.discovery.installation_id {
                return Err(unauthorized());
            }
            if credential.state == "revoked" {
                return Ok(serde_json::json!({
                    "client_id": credential.client_id,
                    "revoked": true
                }));
            }
            if credential.state != "active" {
                return Err(unauthorized());
            }
            credential.instance_id = engine.discovery.instance_id.clone();
            profile
                .save(&credential)
                .map_err(CommandError::connection)?;
            let client = engine
                .client(credential)
                .map_err(CommandError::connection)?;
            let receipt = tokio_runtime()
                .block_on(client.revoke_self())
                .map_err(revocation_error)?;
            let mut stored = profile
                .load()
                .map_err(CommandError::connection)?
                .ok_or_else(unauthorized)?;
            if stored.client_id == receipt.client_id
                && stored.installation_id == engine.discovery.installation_id
            {
                stored.state = "revoked".to_owned();
                stored.secret_hex.clear();
                profile.save(&stored).map_err(CommandError::connection)?;
            }
            serde_json::to_value(receipt).map_err(|_| invalid_error())
        }
    }
}

fn data_root(config: &ConfigFile, config_path: &Path) -> Option<PathBuf> {
    if let Some(value) = config.connection_value("data_root") {
        let path = PathBuf::from(value);
        return path.is_absolute().then_some(path);
    }
    // A selected alternate configuration is isolated unless it explicitly
    // names the engine root. It cannot silently attach to the default profile.
    if std::env::var_os("DISSECT3D_CONFIG_FILE").is_some() {
        return None;
    }
    let home = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }?;
    #[cfg(target_os = "macos")]
    let root = home.join("Library/Application Support/Dissect3D/Engine");
    #[cfg(target_os = "linux")]
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".local/share"))
        .join("dissect3d/engine");
    #[cfg(windows)]
    let root = home.join("Dissect3D/Engine");
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let root = config_path.parent()?.join("dissect3d-engine");
    let _ = config_path;
    Some(root)
}

fn engine_binary(config: &ConfigFile) -> Option<PathBuf> {
    if let Some(binary) = config.connection_value("engine_binary") {
        let path = PathBuf::from(binary);
        return (path.is_absolute() && path.is_file()).then_some(path);
    }
    let current = std::env::current_exe().ok()?;
    let candidate = current.parent()?.join(if cfg!(windows) {
        "dissect3d-engine.exe"
    } else {
        "dissect3d-engine"
    });
    candidate.is_file().then_some(candidate)
}

fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bounded CLI runtime construction")
}

fn unconfigured() -> CommandError {
    CommandError {
        category: "engine_unavailable",
        message: "Configure an absolute engine data root and engine binary for this profile",
        exit_code: 2,
        context: None,
    }
}
fn submission_access_requires_new_profile() -> CommandError {
    CommandError {
        category: "usage_error",
        message: "Submission access can be requested only for a new empty profile",
        exit_code: 2,
        context: None,
    }
}
fn read_unconfigured(status: &'static str) -> impl FnOnce() -> CommandError {
    move || CommandError {
        category: "engine_unavailable",
        message: "Configure an absolute engine data root and engine binary for this profile",
        exit_code: 3,
        context: Some(Box::new(CommandErrorContext {
            data: Some(serde_json::json!({"status": status, "detail": "missing_connection"})),
            ..Default::default()
        })),
    }
}
fn unverified_connection() -> CommandError {
    CommandError {
        category: "engine_unavailable",
        message: "The selected engine is unavailable; authorization could not be verified",
        exit_code: 3,
        context: Some(Box::new(CommandErrorContext {
            data: Some(serde_json::json!({
                "status": "unverified",
                "detail": "engine_unavailable"
            })),
            ..Default::default()
        })),
    }
}
fn unauthorized() -> CommandError {
    CommandError {
        category: "unauthorized",
        message: "This profile has no active engine credential",
        exit_code: 4,
        context: None,
    }
}
fn transport_error() -> CommandError {
    CommandError {
        category: "engine_unavailable",
        message: "The authenticated engine request failed",
        exit_code: 3,
        context: None,
    }
}
fn invalid_error() -> CommandError {
    CommandError {
        category: "invalid_response",
        message: "The selected engine returned an invalid response",
        exit_code: 5,
        context: None,
    }
}

fn unconfirmed_stop() -> CommandError {
    CommandError {
        category: "shutdown_unconfirmed",
        message: "Engine exit was not confirmed; retry with the retained operation identity",
        exit_code: 14,
        context: None,
    }
}

fn unconfirmed_stop_with_receipt(
    operation_id: String,
    operation: serde_json::Value,
) -> CommandError {
    CommandError {
        category: "shutdown_unconfirmed",
        message: "Shutdown was accepted, but process exit was not confirmed before the observation deadline",
        exit_code: 14,
        context: Some(Box::new(CommandErrorContext {
            accepted: Some(serde_json::Value::Bool(true)),
            operation_id: Some(operation_id),
            raw_data: None,
            data: Some(serde_json::json!({
                "operation": operation,
                "process_exit_confirmed": false,
                "pending_record_saved": true
            })),
        })),
    }
}

fn enrollment_error(error: ConnectionError, credential: &ProfileCredential) -> CommandError {
    if matches!(
        error,
        ConnectionError::Unauthorized
            | ConnectionError::Capacity
            | ConnectionError::Conflict
            | ConnectionError::EnrollmentRejected
    ) {
        return CommandError::connection(error);
    }
    CommandError {
        category: "setup_uncertain",
        message: "Enrollment may have committed; retry auth setup with this profile to recover it",
        exit_code: 19,
        context: Some(Box::new(CommandErrorContext {
            data: Some(serde_json::json!({
                "installation_id": credential.installation_id,
                "client_id": credential.client_id,
                "enrollment_id": credential.enrollment_id,
            })),
            ..Default::default()
        })),
    }
}

fn revocation_uncertain() -> CommandError {
    CommandError {
        category: "revocation_uncertain",
        message: "Revocation may have committed; check auth status before another setup",
        exit_code: 19,
        context: None,
    }
}

fn revocation_error(error: dissect3d_api::ClientError) -> CommandError {
    match error {
        dissect3d_api::ClientError::Transport
        | dissect3d_api::ClientError::InvalidResponse
        | dissect3d_api::ClientError::TransferLimit
        | dissect3d_api::ClientError::Incompatible
        | dissect3d_api::ClientError::Rejected(
            dissect3d_api::ErrorCode::PersistenceUnavailable
            | dissect3d_api::ErrorCode::StorageUnavailable,
        ) => revocation_uncertain(),
        error => api_error(error),
    }
}

fn api_error(error: dissect3d_api::ClientError) -> CommandError {
    match error {
        dissect3d_api::ClientError::Rejected(dissect3d_api::ErrorCode::Unauthorized) => {
            unauthorized()
        }
        dissect3d_api::ClientError::Rejected(dissect3d_api::ErrorCode::Busy) => CommandError {
            category: "capacity_rejected",
            message: "The engine could not admit the requested operation",
            exit_code: 7,
            context: None,
        },
        dissect3d_api::ClientError::Incompatible => CommandError {
            category: "incompatible",
            message: "The selected engine does not match this profile or CLI",
            exit_code: 5,
            context: None,
        },
        dissect3d_api::ClientError::TransferLimit
        | dissect3d_api::ClientError::InvalidResponse
        | dissect3d_api::ClientError::InvalidMaterial => invalid_error(),
        dissect3d_api::ClientError::Transport | dissect3d_api::ClientError::Rejected(_) => {
            transport_error()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_opt_in_reaches_connection_without_replacing_its_pending_identity() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        let config: ConfigFile = serde_json::from_value(serde_json::json!({
            "connection": {"data_root": directory.path().join("missing-engine")}
        }))
        .unwrap();
        let profile = Profile::open(&config_path).unwrap();
        let credential = ProfileCredential {
            installation_id: dissect3d_api::InstallationId::parse(
                "ins_0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            instance_id: dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
                .unwrap(),
            client_id: ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
            enrollment_id: EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap(),
            secret_hex: "ab".repeat(32),
            state: "pending".to_owned(),
            submission_access: true,
        };
        profile.save(&credential).unwrap();
        let error = auth(
            AuthCommand::Setup {
                submission_access: true,
            },
            &config,
            &config_path,
            ClientLimits::default(),
        )
        .unwrap_err();
        assert_ne!(
            error.category, "usage_error",
            "an exact pending replay is not a privilege upgrade"
        );
        let stored = profile.load().unwrap().unwrap();
        assert_eq!(stored.client_id, credential.client_id);
        assert_eq!(stored.enrollment_id, credential.enrollment_id);
        assert_eq!(stored.secret_hex, credential.secret_hex);
        assert_eq!(stored.state, "pending");
        assert!(stored.submission_access);
    }

    #[test]
    fn opt_in_enrollment_rejects_existing_profiles_before_engine_connection() {
        for state in ["active", "pending"] {
            let directory = tempfile::tempdir().expect("temporary config root");
            let config_path = directory.path().join("config.json");
            let missing_engine_root = directory.path().join("engine-is-not-running");
            let config: ConfigFile = serde_json::from_value(serde_json::json!({
                "connection": {
                    "data_root": missing_engine_root.to_string_lossy()
                }
            }))
            .expect("isolated connection config");
            let profile = Profile::open(&config_path).expect("profile root");
            let credential = ProfileCredential {
                installation_id: dissect3d_api::InstallationId::parse(
                    "ins_0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                instance_id: dissect3d_api::InstanceId::parse(
                    "eng_0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                client_id: ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
                enrollment_id: EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap(),
                secret_hex: "ab".repeat(32),
                state: state.to_owned(),
                submission_access: false,
            };
            profile.save(&credential).expect("existing profile");

            let error = auth(
                AuthCommand::Setup {
                    submission_access: true,
                },
                &config,
                &config_path,
                ClientLimits::default(),
            )
            .expect_err("must reject before probing the absent engine");
            assert_eq!(error.category, "usage_error");
            assert_eq!(error.exit_code, 2);

            let stored = Profile::open(&config_path)
                .expect("profile root remains available")
                .load()
                .expect("existing profile remains valid")
                .expect("profile remains present");
            assert_eq!(stored.client_id, credential.client_id);
            assert_eq!(stored.enrollment_id, credential.enrollment_id);
            assert_eq!(stored.secret_hex, credential.secret_hex);
            assert_eq!(stored.state, state);
            assert!(!stored.submission_access);
        }
    }

    #[test]
    fn ambiguous_enrollment_is_uncertain_and_keeps_recovery_identity() {
        let credential = ProfileCredential {
            installation_id: dissect3d_api::InstallationId::parse(
                "ins_0123456789abcdef0123456789abcdef",
            )
            .unwrap(),
            instance_id: dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
                .unwrap(),
            client_id: ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
            enrollment_id: EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap(),
            secret_hex: "ab".repeat(32),
            state: "pending".to_owned(),
            submission_access: false,
        };
        for failure in [
            ConnectionError::Unavailable,
            ConnectionError::Invalid,
            ConnectionError::Incompatible,
            ConnectionError::Storage,
        ] {
            let error = enrollment_error(failure, &credential);
            assert_eq!(error.exit_code, 19);
            assert_eq!(error.category, "setup_uncertain");
            let data = error.context.unwrap().data.unwrap();
            assert_eq!(data["enrollment_id"], credential.enrollment_id.as_str());
            assert!(!data.to_string().contains(&credential.secret_hex));
        }
    }

    #[test]
    fn lost_revoke_transport_is_uncertain_but_explicit_rejection_is_not() {
        assert_eq!(revocation_uncertain().category, "revocation_uncertain");
        let lost_receipt = revocation_error(dissect3d_api::ClientError::Transport);
        assert_eq!(lost_receipt.category, "revocation_uncertain");
        assert_eq!(lost_receipt.exit_code, 19);
        assert_eq!(
            revocation_error(dissect3d_api::ClientError::Rejected(
                dissect3d_api::ErrorCode::Unauthorized
            ))
            .exit_code,
            4
        );
        assert_eq!(
            api_error(dissect3d_api::ClientError::Rejected(
                dissect3d_api::ErrorCode::Unauthorized
            ))
            .category,
            "unauthorized"
        );
    }

    #[test]
    fn capacity_rejection_uses_the_admission_failure_contract() {
        let error = api_error(dissect3d_api::ClientError::Rejected(
            dissect3d_api::ErrorCode::Busy,
        ));
        assert_eq!(error.category, "capacity_rejected");
        assert_eq!(error.exit_code, 7);
    }

    #[test]
    fn accepted_shutdown_timeout_retains_receipt_identity_and_data() {
        let operation = serde_json::json!({"operation_id":"op_0123456789abcdef0123456789abcdef"});
        let error = unconfirmed_stop_with_receipt(
            "op_0123456789abcdef0123456789abcdef".to_owned(),
            operation.clone(),
        );
        assert_eq!(error.category, "shutdown_unconfirmed");
        let context = error.context.expect("shutdown result context");
        assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
        assert_eq!(
            context.operation_id.as_deref(),
            Some("op_0123456789abcdef0123456789abcdef")
        );
        assert_eq!(context.data.unwrap()["operation"], operation);
    }

    #[test]
    fn pending_shutdown_receipt_survives_a_later_connection_error() {
        let operation_id = dissect3d_api::OperationId::parse("op_0123456789abcdef0123456789abcdef")
            .expect("operation identity");
        let receipt = dissect3d_api::OperationReceipt {
            api_version: "1.0".to_owned(),
            accepted: true,
            operation_id: operation_id.clone(),
            target: dissect3d_api::OperationTarget {
                kind: "engine".to_owned(),
                instance_id: dissect3d_api::InstanceId::parse(
                    "eng_0123456789abcdef0123456789abcdef",
                )
                .expect("instance identity"),
            },
            state: dissect3d_api::OperationState::Queued,
            replayed: false,
        };
        let pending = PendingStop {
            installation_id: dissect3d_api::InstallationId::parse(
                "ins_0123456789abcdef0123456789abcdef",
            )
            .expect("installation identity"),
            instance_id: receipt.target.instance_id.clone(),
            connection_binding: None,
            pid: 1,
            start_marker: "test-marker".to_owned(),
            idempotency_key: dissect3d_api::IdempotencyKey::parse("pending-stop-test-1")
                .expect("idempotency key"),
            operation_id: Some(operation_id.clone()),
            receipt: Some(receipt),
            state: "pending".to_owned(),
        };
        let error = preserve_pending_receipt(
            CommandError::connection(ConnectionError::Unavailable),
            Some(&pending),
        );
        let context = error.context.expect("known receipt context");
        assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
        assert_eq!(context.operation_id.as_deref(), Some(operation_id.as_str()));
        assert_eq!(
            context.data.as_ref().expect("receipt error data")["pending_record_saved"],
            true
        );

        let persistence_error = shutdown_receipt_storage_error(
            operation_id.as_str().to_owned(),
            serde_json::to_value(pending.receipt.as_ref().unwrap()).unwrap(),
            false,
        );
        let context = persistence_error
            .context
            .expect("receipt survives pending-record persistence failure");
        assert_eq!(context.operation_id.as_deref(), Some(operation_id.as_str()));
        assert_eq!(
            context.data.as_ref().expect("storage error data")["pending_record_saved"],
            false
        );

        let completed = match shutdown_transport_result(
            pending.clone(),
            dissect3d_api::ClientError::Transport,
            true,
        ) {
            Ok(data) => data,
            Err(_) => panic!("confirmed process exit should return completion data"),
        };
        assert_eq!(completed["operation_id"], operation_id.as_str());
        assert_eq!(
            completed["operation"],
            serde_json::to_value(pending.receipt.as_ref().unwrap()).unwrap()
        );
        assert_eq!(completed["process_exit_confirmed"], true);
        assert_eq!(completed["request_error"], transport_error().category);

        let unconfirmed = match shutdown_transport_result(
            pending,
            dissect3d_api::ClientError::Transport,
            false,
        ) {
            Err(error) => error,
            Ok(_) => panic!("unconfirmed process must remain unconfirmed"),
        };
        let context = unconfirmed.context.expect("unconfirmed receipt context");
        assert_eq!(context.operation_id.as_deref(), Some(operation_id.as_str()));
    }
}
