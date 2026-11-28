//! `CR-CS-01` exit regressions for `auth authorize --execution-access` and
//! `auth setup --execution-access` (`WE-P08.1`).

use super::*;
use crate::connection::execution::AuthorizationFailure;
#[cfg(unix)]
use crate::connection::execution::ExchangeFailure;
#[cfg(unix)]
use dissect3d_api::ExecutionAuthorizationReceipt;
use dissect3d_api::{
    EXECUTION_AUTHORIZATION_CONTRACT, EXECUTION_GRANTS, InstallationId, InstanceId,
};

fn installation() -> InstallationId {
    InstallationId::parse("ins_00112233445566778899aabbccddeeff").expect("installation")
}

fn instance() -> InstanceId {
    InstanceId::parse("eng_00112233445566778899aabbccddeeff").expect("instance")
}

fn client_id() -> ClientId {
    ClientId::parse("cli_00112233445566778899aabbccddeeff").expect("client")
}

fn enrollment_id() -> EnrollmentId {
    EnrollmentId::parse("enr_00112233445566778899aabbccddeeff").expect("enrollment")
}

#[cfg(unix)]
fn auth_receipt(authorization_id: &str) -> ExecutionAuthorizationReceipt {
    ExecutionAuthorizationReceipt {
        bootstrap_version: "1.0".into(),
        contract_version: EXECUTION_AUTHORIZATION_CONTRACT.into(),
        installation_id: installation(),
        client_id: client_id(),
        authorization_id: authorization_id.into(),
        grant_policy: EXECUTION_AUTHORIZATION_CONTRACT.into(),
        granted_operations: EXECUTION_GRANTS.iter().map(|g| (*g).into()).collect(),
        replayed: false,
    }
}

fn active_credential() -> ProfileCredential {
    ProfileCredential {
        installation_id: installation(),
        instance_id: instance(),
        client_id: client_id(),
        enrollment_id: enrollment_id(),
        secret_hex: "ab".repeat(32),
        state: "active".into(),
        submission_access: false,
        execution_access: false,
    }
}

#[test]
fn authorize_before_send_maps_incompatible_unavailable_unauthorized_and_storage() {
    let incompatible = authorize::map_authorization_failure(AuthorizationFailure::BeforeSend(
        ConnectionError::Incompatible,
    ));
    assert_eq!(incompatible.exit_code, 5);
    assert_eq!(incompatible.category, "operation_unavailable");

    let unavailable = authorize::map_authorization_failure(AuthorizationFailure::BeforeSend(
        ConnectionError::Unavailable,
    ));
    assert_eq!(unavailable.exit_code, 3);

    let unauthorized = authorize::map_authorization_failure(AuthorizationFailure::BeforeSend(
        ConnectionError::Unauthorized,
    ));
    assert_eq!(unauthorized.exit_code, 4);
    assert_eq!(unauthorized.category, "unauthorized");

    let fresh_storage = authorize::map_authorization_failure(AuthorizationFailure::BeforeSend(
        ConnectionError::Storage,
    ));
    assert_eq!(fresh_storage.exit_code, 6);
    assert_eq!(fresh_storage.category, "storage_error");
}

#[test]
fn authorize_after_write_distinguishes_uncertain_setup_from_explicit_rejection() {
    let uncertain = authorize::map_authorization_failure(AuthorizationFailure::AfterWrite {
        error: ConnectionError::Unavailable,
        client_id: client_id(),
        authorization_id: "aut_00112233445566778899aabbccddeeff".into(),
    });
    assert_eq!(uncertain.exit_code, 19);
    assert_eq!(uncertain.category, "setup_uncertain");
    assert!(
        uncertain
            .message
            .contains("auth authorize --execution-access")
    );
    let data = uncertain.context.as_deref().unwrap().data.as_ref().unwrap();
    assert_eq!(data["client_id"], client_id().as_str());
    assert_eq!(
        data["authorization_id"],
        "aut_00112233445566778899aabbccddeeff"
    );

    let revoked = authorize::map_authorization_failure(AuthorizationFailure::AfterWrite {
        error: ConnectionError::Unauthorized,
        client_id: client_id(),
        authorization_id: "aut_00112233445566778899aabbccddeeff".into(),
    });
    assert_eq!(revoked.exit_code, 4);
    assert_eq!(revoked.category, "unauthorized");
}

#[test]
fn execution_setup_post_receipt_save_failure_exits_19_accepted_true() {
    let mut credential = active_credential();
    credential.execution_access = true;
    let receipt = dissect3d_api::EnrollmentReceipt {
        bootstrap_version: "1.0".into(),
        installation_id: installation(),
        client_id: client_id(),
        enrollment_id: enrollment_id(),
        granted_operations: EXECUTION_GRANTS.iter().map(|g| (*g).into()).collect(),
        created_at_ms: dissect3d_api::TimestampMs::new(1).expect("timestamp"),
        replayed: false,
    };
    let error = auth::save_after_enroll(&credential, &receipt, |_| Err(ConnectionError::Storage))
        .expect_err("unsaved execution enrollment receipt");
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let ctx = error.context.as_deref().unwrap();
    assert_eq!(ctx.accepted, Some(serde_json::Value::Bool(true)));
    let data = ctx.data.as_ref().unwrap();
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["client_id"], client_id().as_str());
    assert_eq!(data["enrollment_id"], enrollment_id().as_str());
    assert_eq!(data["grant_policy"], EXECUTION_AUTHORIZATION_CONTRACT);
    assert!(!data.to_string().contains(&credential.secret_hex));
}

#[cfg(windows)]
#[test]
fn windows_require_native_authority_maps_to_exit_5_operation_unavailable() {
    let error = crate::connection::execution::require_native_authority()
        .map_err(authorize::map_before_send)
        .expect_err("Windows fails closed on native execution authority");
    assert_eq!(error.exit_code, 5);
    assert_eq!(error.category, "operation_unavailable");
}

#[cfg(unix)]
#[test]
fn unix_authorization_record_rewrite_and_receipt_unsaved_follow_cr_cs_01() {
    let temp = tempfile::tempdir().expect("tempdir");
    let config_path = temp.path().join("profile.json");
    let profile = Profile::open(&config_path).expect("open profile");
    profile
        .save(&active_credential())
        .expect("save active credential");

    // First attempt: transport fails after write -> pending record persists.
    let mut auth_id = String::new();
    let first = profile
        .with_execution_authorization(None, |_, pending| {
            auth_id = pending.authorization_id().to_owned();
            Err(ExchangeFailure::AfterWrite(ConnectionError::Unavailable))
        })
        .expect_err("after-write failure");
    let first_err = authorize::map_authorization_failure(first);
    assert_eq!(first_err.exit_code, 19);
    assert_eq!(first_err.category, "setup_uncertain");

    // Second attempt: make the profile directory read-only so reading the existing
    // record succeeds but re-writing it fails -> RecordRewrite (19, accepted: null).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        profile.root().path(),
        std::fs::Permissions::from_mode(0o500),
    )
    .expect("set read-only profile dir");
    let rewrite = profile
        .with_execution_authorization(None, |_, _| unreachable!("must fail before send"))
        .expect_err("rewrite failure");
    std::fs::set_permissions(
        profile.root().path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("restore profile dir permissions");
    let rewrite_err = authorize::map_authorization_failure(rewrite);
    assert_eq!(rewrite_err.exit_code, 19);
    assert_eq!(rewrite_err.category, "recovery_storage_failed");
    let rewrite_ctx = rewrite_err.context.as_deref().unwrap();
    assert!(matches!(
        rewrite_ctx.accepted,
        None | Some(serde_json::Value::Null)
    ));
    let rewrite_data = rewrite_ctx.data.as_ref().unwrap();
    assert_eq!(rewrite_data["receipt_confirmed"], false);
    assert_eq!(rewrite_data["client_id"], client_id().as_str());
    assert_eq!(rewrite_data["authorization_id"], auth_id);

    // Third attempt: receipt arrives, but saving completion fails -> ReceiptUnsaved (19, accepted: true).
    let alias = temp.path().join("complete-block");
    let unsaved = profile
        .with_execution_authorization(None, |_, pending| {
            std::fs::hard_link(
                profile.root().path().join("execution-authorization.json"),
                &alias,
            )
            .expect("hard link before completion");
            Ok(auth_receipt(pending.authorization_id()))
        })
        .expect_err("unsaved receipt");
    std::fs::remove_file(&alias).expect("remove alias");
    let unsaved_err = authorize::map_authorization_failure(unsaved);
    assert_eq!(unsaved_err.exit_code, 19);
    assert_eq!(unsaved_err.category, "recovery_storage_failed");
    let unsaved_ctx = unsaved_err.context.as_deref().unwrap();
    assert_eq!(unsaved_ctx.accepted, Some(serde_json::Value::Bool(true)));
    let unsaved_data = unsaved_ctx.data.as_ref().unwrap();
    assert_eq!(unsaved_data["receipt_confirmed"], true);
    assert_eq!(unsaved_data["client_id"], client_id().as_str());
    assert_eq!(unsaved_data["authorization_id"], auth_id);
    assert_eq!(
        unsaved_data["grant_policy"],
        EXECUTION_AUTHORIZATION_CONTRACT
    );
}
