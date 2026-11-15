use dissect3d_api::*;

const REQUEST: &str = r#"{"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r2","task":{"id":"dissect3d.test.mesh-copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_11111111111111111111111111111111"}]},"parameters":{"n":1.00000000000000000000001},"required_features":["job_execution.we-0.1"],"evaluation_consent":false}"#;

#[test]
fn policy_bounds_closed_fields_and_exact_parameters() {
    for policy in [
        "",
        r#", "execution":{}"#,
        r#", "execution":{"timeout_ms":1}"#,
        r#", "execution":{"timeout_ms":86400000}"#,
    ] {
        let body = format!("{}{policy}}}", &REQUEST[..REQUEST.len() - 1]);
        let request = decode_execution_request(body.as_bytes()).unwrap();
        assert!(
            String::from_utf8(encode_execution_request(&request).unwrap())
                .unwrap()
                .contains("1.00000000000000000000001")
        );
    }
    assert_eq!(
        decode_execution_request(REQUEST.as_bytes())
            .unwrap()
            .execution,
        ExecutionPolicy::default()
    );
    for policy in [
        "null",
        r#"{"timeout_ms":0}"#,
        r#"{"timeout_ms":1.5}"#,
        r#"{"timeout_ms":86400001}"#,
        r#"{"timeout_ms":18446744073709551616}"#,
        r#"{"timeout_ms":null}"#,
        r#"{"timeout_ms":1,"timeout_ms":2}"#,
        r#"{"silent_fallback":true}"#,
    ] {
        let body = format!("{},\"execution\":{policy}}}", &REQUEST[..REQUEST.len() - 1]);
        assert!(
            decode_execution_request(body.as_bytes()).is_err(),
            "{policy}"
        );
    }
    for body in [
        REQUEST.replace("job_execution.we-0.1", "unknown"),
        REQUEST.replace("job_execution.we-0.1", ""),
        REQUEST.replace("\"parameters\":", "\"unknown\":0,\"parameters\":"),
        REQUEST.replace("\"n\":", "\"n\":0,\"n\":"),
    ] {
        assert!(decode_execution_request(body.as_bytes()).is_err());
    }
    assert!(
        decode_job_request(
            REQUEST
                .replace(
                    "\"evaluation_consent\":false",
                    "\"evaluation_consent\":false,\"execution\":{}"
                )
                .as_bytes()
        )
        .is_err()
    );
}

fn snapshot() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("fixtures/execution-snapshot.json"))
        .unwrap()
}

#[test]
fn literal_lifecycle_records_and_rejection() {
    let mut value = snapshot();
    for state in [
        "queued",
        "running",
        "cancel_requested",
        "succeeded",
        "partial",
        "failed",
        "canceled",
        "interrupted",
    ] {
        value["state"] = state.into();
        let raw = serde_json::to_vec(&value).unwrap();
        let parsed: ExecutionJobSnapshot = decode_submission_json(&raw, 262144).unwrap();
        assert!(parsed.validate().is_ok(), "validation failed: {parsed:?}");
        let decoded: ExecutionJobSnapshot =
            decode_execution_json(&serde_json::to_vec(&value).unwrap(), 262144).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), value);
    }
    for (field, bad) in [
        ("state", serde_json::json!("done")),
        ("job_contract", serde_json::json!("we-9")),
        ("result_ids", serde_json::json!(["bad"])),
        ("retry_of", serde_json::json!("bad")),
        (
            "cleanup",
            serde_json::json!({"status":"unknown","reason":null}),
        ),
        ("snapshot_revision", serde_json::json!(0)),
        (
            "progress",
            serde_json::json!({"fraction":1.01,"stage":"copy"}),
        ),
    ] {
        let mut bad_value = value.clone();
        bad_value[field] = bad;
        assert!(
            decode_execution_json::<ExecutionJobSnapshot>(
                &serde_json::to_vec(&bad_value).unwrap(),
                262144
            )
            .is_err(),
            "{field}"
        );
    }
    value.as_object_mut().unwrap().remove("retry_of");
    assert!(
        decode_execution_json::<ExecutionJobSnapshot>(&serde_json::to_vec(&value).unwrap(), 262144)
            .is_err()
    );
    for body in [
        r#"{"api_version":"1.0","required_features":["unknown"]}"#,
        r#"{"api_version":"1.0","required_features":[],"override":true}"#,
        r#"{"api_version":"1.0","required_features":[],"api_version":"1.0"}"#,
    ] {
        assert!(decode_execution_json::<ExecutionControlRequest>(body.as_bytes(), 65536).is_err());
    }
}

#[test]
fn legacy_body_is_accepted_only_as_replay_and_stays_byte_identical() {
    let old = b"{ \"api_version\":\"1.0\",\"support_ref\":\"old\",\"task\":{\"id\":\"copy\",\"version\":\"1.0\"},\"inputs\":{\"mesh\":[{\"input_id\":\"inp_11111111111111111111111111111111\"}]},\"parameters\":{\"n\":1e0},\"required_features\":[],\"evaluation_consent\":false }\n";
    assert!(decode_execution_request(old).is_err());
    let replay = ExecutionSubmissionBody::replay(old.to_vec()).unwrap();
    assert_eq!(replay.as_bytes(), old);
    assert!(ExecutionSubmissionBody::replay(REQUEST.replace("1.0", "9.0").into_bytes()).is_err());
}

#[test]
fn local_request_11_keeps_paths_local_and_rejects_unknown_versions() {
    let body=br#"{"cli_request_version":"1.1","model":"copy","inputs":{"mesh":[{"path":"shape.obj"}]},"parameters":{"n":1.0000000000000000001},"required_features":[],"evaluation_consent":false}"#;
    let local = decode_execution_local_request(body).unwrap();
    assert_eq!(local.inputs["mesh"][0].path, "shape.obj");
    assert_eq!(local.execution, ExecutionPolicy::default());
    for (from, to) in [
        ("1.1", "9.9"),
        ("shape.obj", ""),
        ("\"parameters\":", "\"task\":null,\"parameters\":"),
        (
            "\"required_features\":[]",
            "\"required_features\":[\"unknown\"]",
        ),
    ] {
        assert!(
            decode_execution_local_request(
                String::from_utf8(body.to_vec())
                    .unwrap()
                    .replace(from, to)
                    .as_bytes()
            )
            .is_err()
        );
    }
}

#[test]
fn execution_failures_and_definitive_retry_rejections_decode() {
    for code in [
        "execution_deadline_exceeded",
        "worker_protocol_error",
        "worker_launch_failed",
        "worker_failed",
        "cleanup_unconfirmed",
        "job_not_terminal",
        "retry_prerequisite_unavailable",
    ] {
        let body = format!(
            r#"{{"api_version":"1.0","error":{{"code":"{code}","message":"safe","correlation_id":"corr_11111111111111111111111111111111","retryable":false}}}}"#
        );
        assert!(decode_json::<ApiError>(body.as_bytes()).is_ok(), "{code}");
    }
}
