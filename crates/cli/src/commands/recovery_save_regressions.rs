//! `CR-CS-01` / `CSD-05` seam regressions (S-CR01-6..8) for the exit `6` /
//! exit `19` boundary. Companion to the protected `exit_rule_regressions.rs`.
//!
//! A pending record or credential reused from an earlier attempt may already
//! have reached the engine with its key, so a failure to save it is
//! "acceptance unknown" (exit `19`), even before the new request is sent. An
//! accepted revocation whose profile cannot be reloaded or saved is exit `19`
//! with `accepted: true`.
use super::*;

fn installation() -> dissect3d_api::InstallationId {
    dissect3d_api::InstallationId::parse("ins_00112233445566778899aabbccddeeff")
        .expect("installation identity")
}

fn client_id() -> ClientId {
    ClientId::parse("cli_00112233445566778899aabbccddeeff").expect("client identity")
}

fn pending_stop() -> PendingStop {
    PendingStop {
        installation_id: installation(),
        instance_id: dissect3d_api::InstanceId::parse("eng_00112233445566778899aabbccddeeff")
            .expect("instance identity"),
        connection_binding: None,
        pid: 1,
        start_marker: "seam-marker".to_owned(),
        idempotency_key: IdempotencyKey::parse("key_00112233445566778899aabbccddeeff")
            .expect("idempotency key"),
        operation_id: None,
        receipt: None,
        state: "pending".to_owned(),
    }
}

fn credential() -> ProfileCredential {
    ProfileCredential {
        installation_id: installation(),
        instance_id: dissect3d_api::InstanceId::parse("eng_00112233445566778899aabbccddeeff")
            .expect("instance identity"),
        client_id: client_id(),
        enrollment_id: EnrollmentId::parse("enr_00112233445566778899aabbccddeeff")
            .expect("enrollment identity"),
        secret_hex: "ab".repeat(32),
        state: "pending".to_owned(),
        submission_access: false,
    }
}

fn revocation() -> dissect3d_api::RevocationReceipt {
    dissect3d_api::RevocationReceipt {
        api_version: "1.0".to_owned(),
        client_id: client_id(),
        revoked: true,
        revoked_at_ms: dissect3d_api::TimestampMs::new(1).expect("timestamp"),
    }
}

fn context(error: &CommandError) -> &CommandErrorContext {
    error.context.as_deref().expect("recovery context")
}

fn data(error: &CommandError) -> &serde_json::Value {
    context(error).data.as_ref().expect("recovery data")
}

fn assert_unknown_acceptance(error: &CommandError) {
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    assert!(matches!(
        context(error).accepted,
        None | Some(serde_json::Value::Null)
    ));
    assert_eq!(context(error).operation_id, None);
    assert_eq!(data(error)["receipt_confirmed"], false);
    assert_eq!(data(error)["pending_record_saved"], false);
}

/// S-CR01-6: a retained `pending` stop record without a receipt is reused and
/// fails to save before the new request. Its key may already have reached
/// the engine.
#[test]
fn reused_pending_stop_record_save_failure_exits_19_acceptance_unknown() {
    let error = stop_record_storage_error(&pending_stop(), StopRecord::PossiblySent, false);
    assert_unknown_acceptance(&error);
    assert_eq!(data(&error)["process_exit_confirmed"], false);
}

/// S-CR01-6 companion: a reused record that already holds a receipt reports
/// the accepted shutdown, not a missing prerequisite.
#[test]
fn reused_pending_stop_record_with_receipt_save_failure_exits_19_accepted() {
    let operation_id =
        dissect3d_api::OperationId::parse("op_00112233445566778899aabbccddeeff").expect("op");
    let mut record = pending_stop();
    record.operation_id = Some(operation_id.clone());
    record.receipt = Some(dissect3d_api::OperationReceipt {
        api_version: "1.0".to_owned(),
        accepted: true,
        operation_id: operation_id.clone(),
        target: dissect3d_api::OperationTarget {
            kind: "engine".to_owned(),
            instance_id: record.instance_id.clone(),
        },
        state: dissect3d_api::OperationState::Queued,
        replayed: true,
    });
    let error = stop_record_storage_error(&record, StopRecord::PossiblySent, false);
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    assert_eq!(
        context(&error).accepted,
        Some(serde_json::Value::Bool(true))
    );
    assert_eq!(
        context(&error).operation_id.as_deref(),
        Some(operation_id.as_str())
    );
    assert_eq!(data(&error)["receipt_confirmed"], true);
}

/// S-CR01-7: the engine returned a `RevocationReceipt`; saving the revoked
/// profile fails.
#[test]
fn accepted_revocation_with_unsaved_profile_exits_19() {
    let mut stored = credential();
    stored.state = "active".to_owned();
    let error = record_revocation(
        &revocation(),
        &installation(),
        || Ok(Some(stored)),
        |_| Err(ConnectionError::Storage),
    )
    .expect_err("the save failure is reported");
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    assert_eq!(
        context(&error).accepted,
        Some(serde_json::Value::Bool(true))
    );
    let data = data(&error);
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
    assert_eq!(data["client_id"], client_id().as_str());
    assert!(!data.to_string().contains(&"ab".repeat(32)));
}

/// S-CR01-7: the engine returned a `RevocationReceipt`; reloading the profile
/// fails.
#[test]
fn accepted_revocation_with_unreadable_profile_exits_19() {
    let error = record_revocation(
        &revocation(),
        &installation(),
        || Err(ConnectionError::Storage),
        |_| Ok(()),
    )
    .expect_err("the load failure is reported");
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    assert_eq!(
        context(&error).accepted,
        Some(serde_json::Value::Bool(true))
    );
    assert_eq!(data(&error)["receipt_confirmed"], true);
}

/// The successful revocation clears the stored secret and marks it revoked.
#[test]
fn accepted_revocation_saves_the_revoked_profile() {
    let mut stored = credential();
    stored.state = "active".to_owned();
    let mut saved = None;
    record_revocation(
        &revocation(),
        &installation(),
        || Ok(Some(stored)),
        |record| {
            saved = Some((record.state.clone(), record.secret_hex.clone()));
            Ok(())
        },
    )
    .unwrap_or_else(|_| panic!("the revoked profile is saved"));
    assert_eq!(saved, Some(("revoked".to_owned(), String::new())));
}

/// S-CR01-8: a retained `pending` enrollment credential is reused and fails
/// to save before the new enroll. The earlier enroll may have committed.
#[test]
fn reused_pending_enrollment_save_failure_exits_19_acceptance_unknown() {
    let credential = credential();
    let error = save_before_enroll(&credential, true, |_| Err(ConnectionError::Storage))
        .expect_err("the save failure is reported");
    assert_unknown_acceptance(&error);
    let data = data(&error);
    assert_eq!(data["enrollment_id"], credential.enrollment_id.as_str());
    assert!(!data.to_string().contains(&credential.secret_hex));
}

/// S-CR01-8 guard: a freshly generated credential that fails to save before
/// the first enroll stays exit `6` (nothing can have been accepted).
#[test]
fn fresh_enrollment_save_failure_stays_exit_6() {
    let error = save_before_enroll(&credential(), false, |_| Err(ConnectionError::Storage))
        .expect_err("the save failure is reported");
    assert_eq!(error.exit_code, 6);
    assert_eq!(error.category, "storage_error");
}
