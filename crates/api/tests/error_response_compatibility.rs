use dissect3d_api::{ApiError, AuthRevokeRequest, decode_json};

#[test]
fn ignored_optional_values_keep_the_json_depth_limit() {
    let nested_object_and_array = br#"{"api_version":"1.0","error":{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false,"optional_hint":{"outer":[{"leaf":true}]}}}"#;
    assert!(decode_json::<ApiError>(nested_object_and_array).is_ok());

    let duplicate_inside_ignored_value = br#"{"api_version":"1.0","error":{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false,"optional_hint":{"hint":1,"hint":2}}}"#;
    assert!(decode_json::<ApiError>(duplicate_inside_ignored_value).is_err());

    let within_limit = error_with_nested_hint(30);
    assert!(decode_json::<ApiError>(within_limit.as_bytes()).is_ok());

    let beyond_limit = error_with_nested_hint(31);
    assert!(decode_json::<ApiError>(beyond_limit.as_bytes()).is_err());
}

fn error_with_nested_hint(depth: usize) -> String {
    let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
    format!(
        r#"{{"api_version":"1.0","error":{{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false,"optional_hint":{nested}}}}}"#
    )
}

#[test]
fn error_operation_id_is_preserved_and_request_records_stay_closed() {
    let body = br#"{"api_version":"1.0","error":{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false},"operation_id":"op_0123456789abcdef0123456789abcdef"}"#;
    let decoded: ApiError = decode_json(body).expect("decode compatible error response");
    assert_eq!(
        decoded.operation_id.as_ref().unwrap().as_str(),
        "op_0123456789abcdef0123456789abcdef"
    );
    assert!(
        serde_json::to_value(&decoded)
            .unwrap()
            .get("optional_hint")
            .is_none()
    );

    let request = br#"{"api_version":"1.0","required_features":[],"optional_hint":true}"#;
    assert!(decode_json::<AuthRevokeRequest>(request).is_err());
}
