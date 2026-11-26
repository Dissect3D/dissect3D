//! `CR-CS-01` / `CSD-05` exit-boundary regressions (`CT-CLI-SURFACE §4`).
//!
//! Exit `6` means a local prerequisite is unavailable and no engine request
//! was accepted. Once the engine accepted a request, or acceptance is unknown,
//! a failure to save local recovery state exits `19` with category
//! `recovery_storage_failed`, reporting `accepted` and `receipt_confirmed`.
//!
//! Expected values come from the contract text, not from production helpers.
//! These are unit-level checks through the shared stop helpers, because the
//! CLI binary offers no way to fail a profile save after a receipt.
use super::*;

const OPERATION_ID: &str = "op_fedcba9876543210fedcba9876543210";

fn receipt() -> dissect3d_api::OperationReceipt {
    dissect3d_api::OperationReceipt {
        api_version: "1.0".to_owned(),
        accepted: true,
        operation_id: dissect3d_api::OperationId::parse(OPERATION_ID).expect("operation identity"),
        target: dissect3d_api::OperationTarget {
            kind: "engine".to_owned(),
            instance_id: dissect3d_api::InstanceId::parse("eng_fedcba9876543210fedcba9876543210")
                .expect("instance identity"),
        },
        state: dissect3d_api::OperationState::Queued,
        replayed: false,
    }
}

fn pending(receipt: Option<dissect3d_api::OperationReceipt>) -> PendingStop {
    PendingStop {
        installation_id: dissect3d_api::InstallationId::parse(
            "ins_fedcba9876543210fedcba9876543210",
        )
        .expect("installation identity"),
        instance_id: dissect3d_api::InstanceId::parse("eng_fedcba9876543210fedcba9876543210")
            .expect("instance identity"),
        connection_binding: None,
        pid: 1,
        start_marker: "exit-rule-marker".to_owned(),
        idempotency_key: IdempotencyKey::parse("key_fedcba9876543210fedcba9876543210")
            .expect("idempotency key"),
        operation_id: receipt.as_ref().map(|known| known.operation_id.clone()),
        receipt,
        state: "pending".to_owned(),
    }
}

fn failed_save(_: &PendingStop) -> Result<(), ConnectionError> {
    Err(ConnectionError::Storage)
}

fn context(error: &CommandError) -> &CommandErrorContext {
    error
        .context
        .as_deref()
        .expect("a recovery-storage failure carries JSON context")
}

fn data(error: &CommandError) -> &serde_json::Value {
    context(error)
        .data
        .as_ref()
        .expect("a recovery-storage failure carries data")
}

fn acceptance_unknown(context: &CommandErrorContext) -> bool {
    matches!(context.accepted, None | Some(serde_json::Value::Null))
}

/// S-CR01-1: shutdown accepted (receipt known), saving the receipt fails
/// before process exit is observed.
#[test]
fn accepted_shutdown_with_unsaved_receipt_exits_19_recovery_storage_failed() {
    let operation = serde_json::to_value(receipt()).expect("receipt json");
    let error = shutdown_receipt_storage_error(OPERATION_ID.to_owned(), operation, false);
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let context = context(&error);
    assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
    assert_eq!(context.operation_id.as_deref(), Some(OPERATION_ID));
    let data = data(&error);
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
    assert_eq!(data["process_exit_confirmed"], false);
}

/// S-CR01-2: shutdown accepted, process exit confirmed, saving the completed
/// record fails.
#[test]
fn accepted_shutdown_with_confirmed_exit_and_unsaved_record_exits_19() {
    let mut record = pending(Some(receipt()));
    let error =
        record_confirmed_exit(&mut record, failed_save).expect_err("the save failure is reported");
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let context = context(&error);
    assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
    assert_eq!(context.operation_id.as_deref(), Some(OPERATION_ID));
    let data = data(&error);
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["process_exit_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
}

/// S-CR01-3: the stop request was sent but no receipt is known (lost
/// response, or an offline retry of a retained pending record). Process exit
/// is confirmed and saving fails. Acceptance is unknown, so exit 6 is wrong.
#[test]
fn no_receipt_stop_with_unsaved_record_exits_19_with_receipt_unconfirmed() {
    let mut record = pending(None);
    let error =
        record_confirmed_exit(&mut record, failed_save).expect_err("the save failure is reported");
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let context = context(&error);
    assert!(acceptance_unknown(context), "acceptance stays unknown");
    assert_eq!(context.operation_id, None);
    let data = data(&error);
    assert_eq!(data["receipt_confirmed"], false);
    assert_eq!(data["process_exit_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
}

/// S-CR01-4: a fresh pending record (no earlier attempt, no receipt) fails to
/// save before the request is sent. Nothing can have been accepted: exit 6
/// stays. Expected to pass already; it guards the boundary against
/// over-correction.
#[test]
fn fresh_pre_request_stop_record_failure_stays_exit_6() {
    let error = pending_stop_storage_error(&pending(None), false);
    assert_eq!(error.exit_code, 6);
    assert_eq!(error.category, "storage_error");
    let context = context(&error);
    assert!(acceptance_unknown(context), "nothing accepted is claimed");
    assert_eq!(data(&error)["process_exit_confirmed"], false);
}

/// S-CR01-5: the pre-request mapping shared by credential, profile and pending
/// record storage stays exit 6 (same boundary as protected
/// `crates/cli/tests/core_service.rs` missing-credential check).
#[test]
fn pre_request_profile_storage_failure_stays_exit_6() {
    let error = CommandError::connection(ConnectionError::Storage);
    assert_eq!(error.exit_code, 6);
    assert_eq!(error.category, "storage_error");
}
