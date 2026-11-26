//! 2026-11-13 defect regression (`CS-S15`, `CSC-005`): after process exit was
//! confirmed, a failed local save of the completed pending-stop record was
//! reported as `process_exit_confirmed: false`, or without any process
//! outcome when no receipt was known. Every confirmed-exit path in `stop`
//! (offline target gone, lost response then observed exit, receipt then
//! observed exit) now records completion through `record_confirmed_exit`.
use super::*;

fn receipt() -> dissect3d_api::OperationReceipt {
    dissect3d_api::OperationReceipt {
        api_version: "1.0".to_owned(),
        accepted: true,
        operation_id: dissect3d_api::OperationId::parse("op_0123456789abcdef0123456789abcdef")
            .expect("operation identity"),
        target: dissect3d_api::OperationTarget {
            kind: "engine".to_owned(),
            instance_id: dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
                .expect("instance identity"),
        },
        state: dissect3d_api::OperationState::Queued,
        replayed: false,
    }
}

fn pending(receipt: Option<dissect3d_api::OperationReceipt>) -> PendingStop {
    PendingStop {
        installation_id: dissect3d_api::InstallationId::parse(
            "ins_0123456789abcdef0123456789abcdef",
        )
        .expect("installation identity"),
        instance_id: dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef")
            .expect("instance identity"),
        connection_binding: None,
        pid: 1,
        start_marker: "test-marker".to_owned(),
        idempotency_key: IdempotencyKey::parse("key_0123456789abcdef0123456789abcdef")
            .expect("idempotency key"),
        operation_id: receipt.as_ref().map(|known| known.operation_id.clone()),
        receipt,
        state: "pending".to_owned(),
    }
}

fn failed_save(_: &PendingStop) -> Result<(), ConnectionError> {
    Err(ConnectionError::Storage)
}

fn error_data(error: &CommandError) -> &serde_json::Value {
    error
        .context
        .as_ref()
        .and_then(|context| context.data.as_ref())
        .expect("storage failure keeps the stop outcome")
}

#[test]
fn confirmed_exit_with_a_receipt_survives_a_failed_local_save() {
    let mut record = pending(Some(receipt()));
    let error =
        record_confirmed_exit(&mut record, failed_save).expect_err("the save failure is reported");
    assert_eq!(error.category, "recovery_storage_failed");
    assert_eq!(error.exit_code, 19);
    let context = error.context.as_ref().expect("receipt context");
    assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
    assert_eq!(
        context.operation_id.as_deref(),
        Some("op_0123456789abcdef0123456789abcdef")
    );
    let data = error_data(&error);
    assert_eq!(data["process_exit_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
}

#[test]
fn confirmed_exit_without_a_receipt_survives_a_failed_local_save() {
    let mut record = pending(None);
    let error =
        record_confirmed_exit(&mut record, failed_save).expect_err("the save failure is reported");
    assert_eq!(error.category, "recovery_storage_failed");
    assert_eq!(error.exit_code, 19);
    let context = error.context.as_ref().expect("process outcome context");
    assert_eq!(context.accepted, None, "acceptance stays unknown");
    let data = error_data(&error);
    assert_eq!(data["process_exit_confirmed"], true);
    assert_eq!(data["receipt_confirmed"], false);
    assert_eq!(data["pending_record_saved"], false);
}

#[test]
fn confirmed_exit_saves_the_completed_record() {
    let mut record = pending(Some(receipt()));
    let mut saved_state = None;
    let saved = record_confirmed_exit(&mut record, |stored| {
        saved_state = Some(stored.state.clone());
        Ok(())
    });
    assert!(saved.is_ok());
    assert_eq!(saved_state.as_deref(), Some("complete"));
    assert_eq!(
        pending_stop_data(&record, true)["process_exit_confirmed"],
        true
    );
}

#[test]
fn a_save_before_the_request_never_claims_process_exit() {
    let error = pending_stop_storage_error(&pending(None), false);
    assert_eq!(error_data(&error)["process_exit_confirmed"], false);
}
