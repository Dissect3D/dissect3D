fn numeric_receipt() -> AcceptanceReceipt {
    let mut receipt: AcceptanceReceipt = dissect3d_api::decode_submission_json(
        include_bytes!("../../../tests/fixtures/illustrative-acceptance.json"),
        262_144,
    )
    .unwrap();
    receipt.resolved.effective_parameters = dissect3d_api::decode_submission_json(
        br#"{"adjacent":9007199254740993,"precise":9007199254740993.0000000000000001,"exponent":1.2300e2,"negative":-9223372036854775808,"large_decimal":1e308,"small_decimal":1e-308,"wide_decimal":123456789012345678901234567890123456789012345678901234567891e308}"#,
        262_144,
    ).unwrap();
    receipt
}

#[test]
fn accepted_output_retains_complete_numeric_receipt() {
    let c = control();
    let receipt = numeric_receipt();
    c.accepted(receipt.clone());
    let data = c.accepted_data().unwrap();
    let bytes = serde_json::to_vec(&data).unwrap();
    let fields: std::collections::BTreeMap<String, dissect3d_api::SubmissionValue> =
        dissect3d_api::decode_submission_json(&bytes, 262_144).unwrap();
    assert!(fields.contains_key("resolved"), "resolved receipt missing");
    let mut decoded_fields = fields;
    decoded_fields.remove("sub_id");
    let roundtrip: AcceptanceReceipt = dissect3d_api::decode_submission_json(
        &serde_json::to_vec(&decoded_fields).unwrap(),
        262_144,
    )
    .unwrap();
    assert_eq!(roundtrip, receipt);
    let encoded = String::from_utf8(bytes).unwrap();
    assert!(encoded.contains("9007199254740993.0000000000000001"));
    assert!(encoded.contains("1.2300e2"));
}

#[test]
fn interruption_and_known_acceptance_errors_preserve_numeric_receipt() {
    let c = control();
    let receipt = numeric_receipt();
    c.accepted(receipt.clone());
    let interrupted = c
        .interrupt_outcome()
        .unwrap_or_else(|_| panic!("known acceptance"));
    assert_eq!(interrupted.receipt, receipt);
    for category in ["recovery_storage_failed", "submission_uncertain"] {
        let error = c.preserve_known(super::super::failure(
            category,
            "test error",
            15,
            None,
            None,
        ));
        assert_eq!(error.exit_code, 19);
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
        let encoded = serde_json::to_vec(&outcome).unwrap();
        #[derive(serde::Deserialize)]
        struct Envelope {
            accepted: bool,
            data: Box<serde_json::value::RawValue>,
        }
        let envelope: Envelope = serde_json::from_slice(&encoded).unwrap();
        assert!(envelope.accepted);
        let decoded: AcceptanceReceipt =
            dissect3d_api::decode_submission_json(envelope.data.get().as_bytes(), 262_144).unwrap();
        assert_eq!(decoded, receipt);
    }
    let raw = serde_json::value::to_raw_value(&interrupted).unwrap();
    let outcome = crate::output::CommandOutcome::success_raw("jobs submit", raw);
    let encoded = serde_json::to_vec(&outcome).unwrap();
    assert!(
        String::from_utf8(encoded)
            .unwrap()
            .contains("9007199254740993.0000000000000001")
    );
}
