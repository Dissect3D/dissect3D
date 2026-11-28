//! CR-CS-01 recovery-save and control-error regressions for `jobs retry`,
//! `jobs recover` on retry records, and `jobs cancel` (`WE-P08.4`).

use crate::commands::execution::submit::{
    persist_fresh_execution_record, preserve_execution_recovery_status,
    save_execution_receipt_or_cr_cs_01,
};
use crate::commands::job_control::cancel_send_error;
use crate::connection::Profile;
use crate::submissions::execution::PendingExecutionRecord;
use crate::submissions::{AnyPendingRecord, RecordError, SubmissionRecords};
use dissect3d_api::{
    ApiError, ApiErrorBody, ClientError, ClientId, CorrelationId, ErrorCode, ExecutionAcceptance,
    ExecutionJobSnapshot, IdempotencyKey, InstallationId, JOB_CONTRACT, JobId,
    SubmissionClientError, SubmissionId, decode_execution_json,
};

fn source_job_id() -> JobId {
    JobId::parse("job_00000000000000000000000000000001").unwrap()
}

fn retried_job_id() -> JobId {
    JobId::parse("job_00000000000000000000000000000002").unwrap()
}

fn retry_record(receipt: Option<ExecutionAcceptance>) -> PendingExecutionRecord {
    PendingExecutionRecord {
        record_version: "1.1".into(),
        sub_id: SubmissionId::parse("sub_11111111111111111111111111111111").unwrap(),
        installation_id: InstallationId::parse("ins_11111111111111111111111111111111").unwrap(),
        client_id: ClientId::parse("cli_11111111111111111111111111111111").unwrap(),
        operation: "jobs.retry".into(),
        key: IdempotencyKey::parse("retry-exact-key-1").unwrap(),
        job_contract: JOB_CONTRACT.into(),
        request_body_utf8: None,
        source_job_id: Some(source_job_id()),
        input_identities: Vec::new(),
        receipt,
    }
}

fn retry_acceptance() -> ExecutionAcceptance {
    let snap: ExecutionJobSnapshot = decode_execution_json(
        include_bytes!("../../../../api/tests/fixtures/execution-snapshot.json"),
        262_144,
    )
    .unwrap();
    ExecutionAcceptance {
        api_version: "1.0".into(),
        accepted: true,
        job_id: retried_job_id(),
        replayed: false,
        acceptance_sequence: 2,
        snapshot_revision: 1,
        resolved: snap.resolved,
        job_contract: JOB_CONTRACT.into(),
        retry_of: Some(source_job_id()),
    }
}

#[test]
fn retry_receipt_save_failure_exits_19_accepted_true_with_retry_of() {
    let record = retry_record(None);
    let acceptance = retry_acceptance();
    let err =
        save_execution_receipt_or_cr_cs_01(&record, &acceptance, |_, _| Err(RecordError::Storage))
            .err()
            .unwrap();
    assert_eq!(err.exit_code, 19);
    assert_eq!(err.category, "recovery_storage_failed");
    let ctx = err.context.as_deref().unwrap();
    assert_eq!(ctx.accepted, Some(serde_json::Value::Bool(true)));
    let data = ctx.data.as_ref().unwrap();
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
    assert_eq!(data["sub_id"], record.sub_id.as_str());
    assert_eq!(data["job_id"], acceptance.job_id.as_str());
    assert_eq!(data["retry_of"], source_job_id().as_str());
}

#[test]
fn retry_record_persists_exact_key_and_source_for_recover() {
    let dir = tempfile::tempdir().unwrap();
    let profile = Profile::open(&dir.path().join("profile.json")).unwrap();
    let record = retry_record(None);
    let lease = persist_fresh_execution_record(&profile, &record)
        .ok()
        .unwrap();
    let acceptance = retry_acceptance();
    lease.save_receipt(&record, acceptance.clone()).unwrap();
    drop(lease);

    let records = SubmissionRecords::lock(&profile).unwrap();
    let AnyPendingRecord::Execution(loaded) = records.load_any(&record.sub_id).unwrap() else {
        panic!("expected 1.1 retry record");
    };
    assert_eq!(loaded.operation, "jobs.retry");
    assert_eq!(loaded.key, record.key);
    assert_eq!(loaded.source_job_id, Some(source_job_id()));
    assert_eq!(
        loaded.receipt.as_ref().map(|r| &r.job_id),
        Some(&acceptance.job_id)
    );
}

#[test]
fn retry_recovery_with_saved_receipt_preserves_accepted_true_on_transport_error() {
    let record = retry_record(Some(retry_acceptance()));
    let err = crate::commands::CommandError {
        category: "engine_unavailable",
        message: "engine unavailable",
        exit_code: 3,
        context: None,
    };
    let preserved = preserve_execution_recovery_status(err, &record);
    assert_eq!(preserved.exit_code, 3);
    let ctx = preserved.context.as_deref().unwrap();
    assert_eq!(ctx.accepted, Some(serde_json::Value::Bool(true)));
    let raw = ctx.raw_data.as_deref().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(raw.get()).unwrap();
    assert_eq!(parsed["job_id"], retried_job_id().as_str());
    assert_eq!(parsed["retry_of"], source_job_id().as_str());
}

#[test]
fn cancel_transport_after_send_exits_19_with_job_id_and_before_send_exits_3() {
    let id = source_job_id();
    let uncertain = cancel_send_error(
        SubmissionClientError::Uncertain {
            correlation_id: None,
        },
        &id,
    );
    assert_eq!(uncertain.exit_code, 19);
    assert_eq!(uncertain.category, "cancel_uncertain");
    let data = uncertain.context.as_deref().unwrap().data.as_ref().unwrap();
    assert_eq!(data["job_id"], id.as_str());
    assert!(data.get("correlation_id").is_none());

    let before = cancel_send_error(
        SubmissionClientError::BeforeSend(ClientError::Transport),
        &id,
    );
    assert_eq!(before.exit_code, 3);

    let not_found = cancel_send_error(
        SubmissionClientError::Rejected(Box::new(ApiError {
            api_version: "1.0".into(),
            error: ApiErrorBody {
                code: ErrorCode::NotFound,
                message: "not found".into(),
                correlation_id: CorrelationId::parse("corr_0123456789abcdef0123456789abcdef")
                    .unwrap(),
                retryable: false,
                details: None,
            },
            operation_id: None,
        })),
        &id,
    );
    assert_eq!(not_found.exit_code, 19);
    assert_eq!(not_found.category, "not_found");
}

#[test]
fn capacity_and_storage_rejections_map_to_exit_7_like_feat_03() {
    let id = source_job_id();
    let sub_id = SubmissionId::parse("sub_11111111111111111111111111111111").unwrap();
    let key = IdempotencyKey::parse("retry-exact-key-1").unwrap();
    for code in [
        ErrorCode::CapacityExceeded,
        ErrorCode::Busy,
        ErrorCode::PersistenceUnavailable,
        ErrorCode::StorageUnavailable,
        ErrorCode::StoreUnavailable,
    ] {
        let rejection = || {
            SubmissionClientError::Rejected(Box::new(ApiError {
                api_version: "1.0".into(),
                error: ApiErrorBody {
                    code,
                    message: "unavailable".into(),
                    correlation_id: CorrelationId::parse("corr_0123456789abcdef0123456789abcdef")
                        .unwrap(),
                    retryable: true,
                    details: None,
                },
                operation_id: None,
            }))
        };
        assert_eq!(
            cancel_send_error(rejection(), &id).exit_code,
            7,
            "cancel {code:?}"
        );
        assert_eq!(
            crate::commands::execution::execution_send_error(rejection(), &sub_id, &key, false)
                .exit_code,
            7,
            "retry/submit {code:?}"
        );
    }
}
