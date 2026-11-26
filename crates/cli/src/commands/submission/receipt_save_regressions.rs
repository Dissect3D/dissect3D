// CR-CS-01 (`CT-CLI-SURFACE §4` row 19, `CSD-04`/`CSD-05`): when the engine
// accepted a job but `send_record` cannot save the local receipt, FEAT-03
// reports the same `recovery_storage_failed` shape as FEAT-01, through the
// shared `CommandError::recovery_save_failure` rule.

fn unsaved_receipt_fixture() -> super::super::SubmissionSuccess {
    super::super::SubmissionSuccess {
        sub_id: Some(SubmissionId::parse("sub_0123456789abcdef0123456789abcdef").unwrap()),
        receipt: numeric_receipt(),
    }
}

#[test]
fn unsaved_receipt_error_reports_shared_recovery_save_context() {
    let success = unsaved_receipt_fixture();
    let error = super::super::unsaved_receipt_error(&success);
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let context = error.context.expect("context is reported");
    assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
    assert_eq!(context.operation_id, None);
    let data = context.data.expect("identity and facts are reported");
    assert_eq!(data["receipt_confirmed"], true);
    assert_eq!(data["pending_record_saved"], false);
    assert_eq!(data["sub_id"], "sub_0123456789abcdef0123456789abcdef");
    assert_eq!(
        data["job_id"],
        serde_json::to_value(&success.receipt.job_id).unwrap()
    );
}

#[test]
fn known_acceptance_output_keeps_recovery_save_facts_and_lossless_receipt() {
    let c = control();
    let success = unsaved_receipt_fixture();
    c.local_id(success.sub_id.clone().unwrap());
    c.accepted(success.receipt.clone());
    let error = c.preserve_known(super::super::unsaved_receipt_error(&success));
    assert_eq!(error.exit_code, 19);
    assert_eq!(error.category, "recovery_storage_failed");
    let context = error.context.unwrap();
    assert_eq!(context.accepted, Some(serde_json::Value::Bool(true)));
    let outcome = crate::output::CommandOutcome::failure_with_context(
        "jobs submit",
        crate::output::ErrorInfo::new(error.category, error.message),
        context.accepted,
        context.operation_id,
        context.data,
    )
    .with_raw_data(context.raw_data);
    let encoded = String::from_utf8(serde_json::to_vec(&outcome).unwrap()).unwrap();
    assert!(encoded.contains("9007199254740993.0000000000000001"));
    let fields: std::collections::BTreeMap<String, dissect3d_api::SubmissionValue> =
        dissect3d_api::decode_submission_json(encoded.as_bytes(), 262_144).unwrap();
    let data: std::collections::BTreeMap<String, dissect3d_api::SubmissionValue> =
        dissect3d_api::decode_submission_json(
            &serde_json::to_vec(&fields["data"]).unwrap(),
            262_144,
        )
        .unwrap();
    let text = |key: &str| serde_json::to_string(&data[key]).unwrap();
    assert_eq!(text("receipt_confirmed"), "true");
    assert_eq!(text("pending_record_saved"), "false");
    assert_eq!(text("sub_id"), "\"sub_0123456789abcdef0123456789abcdef\"");
    assert_eq!(
        text("job_id"),
        serde_json::to_string(&success.receipt.job_id).unwrap()
    );
    assert!(data.contains_key("resolved"), "receipt is preserved");
}

#[test]
fn known_acceptance_without_recovery_save_facts_is_unchanged() {
    let c = control();
    let success = unsaved_receipt_fixture();
    c.local_id(success.sub_id.clone().unwrap());
    c.accepted(success.receipt.clone());
    let error = c.preserve_known(super::super::failure(
        "submission_uncertain",
        "test error",
        15,
        None,
        None,
    ));
    let raw = error.context.unwrap().raw_data.unwrap();
    assert_eq!(
        raw.get(),
        serde_json::value::to_raw_value(&success).unwrap().get()
    );
}
