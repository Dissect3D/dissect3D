use dissect3d_api::{
    EngineInfo, InputId, JobRequest, SubmissionId, SubmissionValue, decode_job_request,
    decode_json, decode_submission_json, encode_job_request,
};
use serde::Deserialize;

const INPUT_ID: &str = "inp_0123456789abcdef0123456789abcdef";

fn request_with_parameters(parameters: &str) -> Vec<u8> {
    format!(
        r#"{{"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r1","task":{{"id":"dissect3d.test.mesh-copy","version":"1.0"}},"inputs":{{"mesh":[{{"input_id":"{INPUT_ID}"}}]}},"parameters":{parameters},"required_features":[],"evaluation_consent":false}}"#
    )
    .into_bytes()
}

fn replace_json_member(bytes: &[u8], member: &str, old_value: &str, value: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("request JSON is UTF-8");
    let marker = format!(
        "\"{member}\":{}",
        serde_json::to_string(old_value).expect("encode old member")
    );
    let encoded = serde_json::to_string(value).expect("encode string member");
    text.replace(&marker, &format!("\"{member}\":{encoded}"))
        .into_bytes()
}

fn insert_optional_string_member(bytes: &[u8], member: &str, value: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("request JSON is UTF-8");
    text.replace(
        "\"inputs\":",
        &format!(
            "\"{member}\":{},\"inputs\":",
            serde_json::to_string(value).expect("encode optional string")
        ),
    )
    .into_bytes()
}

#[test]
fn job_request_preserves_omissions_and_exact_numeric_kinds() {
    let bytes = request_with_parameters(
        r#"{"decimal":1.0,"large_integer":9007199254740993,"nested":{"é":"é"},"scientific":1e0}"#,
    );
    let request = decode_job_request(&bytes).expect("valid strict job request");

    assert_eq!(request.runtime_ref, None);
    assert_eq!(request.variant, None);
    assert_eq!(request.inputs["mesh"][0].input_id.as_str(), INPUT_ID);
    assert!(matches!(
        request.parameters.get("large_integer"),
        Some(SubmissionValue::Integer(9_007_199_254_740_993))
    ));
    assert!(matches!(
        request.parameters.get("decimal"),
        Some(SubmissionValue::Decimal(value)) if value.as_str() == "1.0"
    ));
    assert!(matches!(
        request.parameters.get("scientific"),
        Some(SubmissionValue::Decimal(value)) if value.as_str() == "1e0"
    ));

    let encoded = encode_job_request(&request).expect("lossless deterministic encoding");
    assert_eq!(
        encoded,
        r#"{"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r1","task":{"id":"dissect3d.test.mesh-copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_0123456789abcdef0123456789abcdef"}]},"parameters":{"decimal":1.0,"large_integer":9007199254740993,"nested":{"é":"é"},"scientific":1e0},"required_features":[],"evaluation_consent":false}"#
            .as_bytes()
    );
}

#[test]
fn job_request_rejects_duplicate_or_unknown_members_at_every_depth() {
    for bytes in [
        request_with_parameters(r#"{"nested":{"enabled":true,"enabled":false}}"#),
        request_with_parameters(r#"{"nested":{"enabled":true},"nested":{}}"#),
        br#"{"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r1","task":{"id":"dissect3d.test.mesh-copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_0123456789abcdef0123456789abcdef","path":"private"}]},"parameters":{},"required_features":[],"evaluation_consent":false}"#.to_vec(),
        br#"{"api_version":"1.0","support_ref":"test.mesh-copy@fixture-r1","task":{"id":"dissect3d.test.mesh-copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_0123456789abcdef0123456789abcdef"}]},"parameters":{},"required_features":[],"evaluation_consent":false,"future_required_behavior":true}"#.to_vec(),
        request_with_parameters(r#"{"x":null}"#).into_iter().chain(b" {}".iter().copied()).collect(),
    ] {
        assert!(decode_job_request(&bytes).is_err());
    }

    let mut invalid_utf8 = request_with_parameters(r#"{"text":"safe"}"#);
    let safe = invalid_utf8
        .windows(4)
        .position(|window| window == b"safe")
        .expect("literal input contains safe");
    invalid_utf8[safe] = 0xff;
    assert!(decode_job_request(&invalid_utf8).is_err());
}

#[test]
fn job_request_enforces_exact_numeric_token_and_integer_limits() {
    for number in [
        "1e309",
        "9223372036854775808",
        "0.123456789012345678901234567890123456789012345678901234567890123",
        "NaN",
        "\"\\ud800\"",
    ] {
        assert!(
            decode_job_request(&request_with_parameters(&format!(r#"{{"n":{number}}}"#))).is_err(),
            "accepted invalid token: {number}"
        );
    }

    let sixty_four_bytes = format!("0.{}", "1".repeat(62));
    let request = decode_job_request(&request_with_parameters(&format!(
        r#"{{"n":{sixty_four_bytes}}}"#
    )))
    .expect("64-byte numeric token is within the contract cap");
    assert!(matches!(
        request.parameters.get("n"),
        Some(SubmissionValue::Decimal(value)) if value.as_str() == sixty_four_bytes
    ));
}

#[test]
fn job_request_enforces_the_thirty_two_container_depth_limit() {
    let accepted = format!("{{\"nested\":{}0{}}}", "[".repeat(30), "]".repeat(30));
    assert!(decode_job_request(&request_with_parameters(&accepted)).is_ok());

    let rejected = format!("{{\"nested\":{}0{}}}", "[".repeat(31), "]".repeat(31));
    assert!(decode_job_request(&request_with_parameters(&rejected)).is_err());
}

#[test]
fn submission_identifiers_reject_noncanonical_spellings() {
    assert!(InputId::parse(INPUT_ID).is_ok());
    assert!(SubmissionId::parse("sub_0123456789abcdef0123456789abcdef").is_ok());
    assert!(InputId::parse("inp_0123456789ABCDEF0123456789abcdef").is_err());
    assert!(InputId::parse("inp_../0123456789abcdef0123456789abcdef").is_err());
    assert!(SubmissionId::parse("sub_0123456789abcdef0123456789abcde").is_err());
}

#[test]
fn engine_info_accepts_an_optional_submission_capability_and_older_peers() {
    let legacy = br#"{"api_version":"1.0","engine_version":"0.1.0","installation_id":"ins_0123456789abcdef0123456789abcdef","instance_id":"eng_0123456789abcdef0123456789abcdef","phase":"ready","supported_operations":["engine.info"],"granted_operations":["engine.info"],"required_features":[],"limits":{},"platform":{"os":"windows","architecture":"x86_64"}}"#;
    let info: EngineInfo = decode_json(legacy).expect("older core response remains compatible");
    assert!(info.submission.is_none());

    let with_capability = br#"{"api_version":"1.0","engine_version":"0.1.0","installation_id":"ins_0123456789abcdef0123456789abcdef","instance_id":"eng_0123456789abcdef0123456789abcdef","phase":"ready","supported_operations":["engine.info"],"granted_operations":["engine.info"],"required_features":[],"limits":{},"platform":{"os":"windows","architecture":"x86_64"},"submission":{"version":"1.0","dispatch_enabled":false,"operations":["inputs.create","jobs.submit","jobs.list","jobs.show"],"limits":{"input_bytes_max":268435456},"limits_source":"built_in"}}"#;
    let info: EngineInfo = decode_json(with_capability).expect("optional Stage 3 capability");
    let capability = info.submission.expect("capability present");
    assert_eq!(capability.version, "1.0");
    assert!(!capability.dispatch_enabled);
    assert_eq!(capability.operations.len(), 4);
    assert_eq!(capability.limits["input_bytes_max"], 268_435_456);
    assert_eq!(capability.limits_source, "built_in");
}

#[test]
fn job_request_type_remains_constructible_for_client_encoding() {
    // This assertion protects the shared request type's role and typed tree,
    // while the literal JSON test above remains the independent expectation.
    fn accepts_request(_: &JobRequest) {}
    let request = decode_job_request(&request_with_parameters("{}"))
        .expect("valid request for shared client");
    accepts_request(&request);
}

#[test]
fn strict_response_decoder_keeps_parameter_number_lexemes_and_rejects_duplicates() {
    let decoded: std::collections::BTreeMap<String, SubmissionValue> =
        decode_submission_json(br#"{"decimal":1.00,"integer":9007199254740993}"#, 1024)
            .expect("bounded strict response");
    assert!(matches!(
        decoded.get("decimal"),
        Some(SubmissionValue::Decimal(value)) if value.as_str() == "1.00"
    ));
    assert!(matches!(
        decoded.get("integer"),
        Some(SubmissionValue::Integer(9_007_199_254_740_993))
    ));
    assert!(
        decode_submission_json::<std::collections::BTreeMap<String, SubmissionValue>>(
            br#"{"x":1,"x":2}"#,
            1024
        )
        .is_err()
    );
}

#[derive(Deserialize)]
struct SubmissionVectors {
    cases: Vec<SubmissionVectorCase>,
    invalid_json: Vec<String>,
    literal_canonical: Vec<SubmissionLiteral>,
}

#[derive(Deserialize)]
struct SubmissionVectorCase {
    left: String,
    right: String,
}

#[derive(Deserialize)]
struct SubmissionLiteral {
    raw: String,
}

#[test]
fn independent_submission_literals_exercise_strict_json_tokens() {
    let vectors: SubmissionVectors =
        serde_json::from_str(include_str!("fixtures/submission-vectors.json"))
            .expect("protected independent Stage 3 vectors");
    for case in vectors.cases {
        assert!(decode_submission_json::<SubmissionValue>(case.left.as_bytes(), 65_536).is_ok());
        assert!(decode_submission_json::<SubmissionValue>(case.right.as_bytes(), 65_536).is_ok());
    }
    for literal in vectors.literal_canonical {
        assert!(decode_submission_json::<SubmissionValue>(literal.raw.as_bytes(), 65_536).is_ok());
    }
    for invalid in vectors.invalid_json {
        assert!(
            decode_submission_json::<SubmissionValue>(invalid.as_bytes(), 65_536).is_err(),
            "accepted invalid independent literal: {invalid}"
        );
    }
}

#[test]
fn job_request_enforces_string_collection_and_body_boundaries() {
    for length in [1_024, 1_025] {
        let value = "é".repeat(length);
        let request = replace_json_member(
            &request_with_parameters("{}"),
            "support_ref",
            "test.mesh-copy@fixture-r1",
            &value,
        );
        assert_eq!(
            decode_job_request(&request).is_ok(),
            length == 1_024,
            "support_ref character limit {length}"
        );
    }
    for length in [1_024, 1_025] {
        let value = "t".repeat(length);
        let request = replace_json_member(
            &request_with_parameters("{}"),
            "id",
            "dissect3d.test.mesh-copy",
            &value,
        );
        assert_eq!(
            decode_job_request(&request).is_ok(),
            length == 1_024,
            "task ID character limit {length}"
        );
    }
    for length in [32, 33] {
        let value = format!("1.{}", "0".repeat(length - 2));
        let request = replace_json_member(&request_with_parameters("{}"), "version", "1.0", &value);
        assert_eq!(
            decode_job_request(&request).is_ok(),
            length == 32,
            "task version character limit {length}"
        );
    }
    for length in [128, 129] {
        let value = "v".repeat(length);
        let request =
            insert_optional_string_member(&request_with_parameters("{}"), "variant", &value);
        assert_eq!(
            decode_job_request(&request).is_ok(),
            length == 128,
            "variant character limit {length}"
        );
    }
    for length in [1_024, 1_025] {
        let value = "r".repeat(length);
        let request =
            insert_optional_string_member(&request_with_parameters("{}"), "runtime_ref", &value);
        assert_eq!(
            decode_job_request(&request).is_ok(),
            length == 1_024,
            "runtime_ref character limit {length}"
        );
    }

    for length in [128, 129] {
        let feature = "f".repeat(length);
        let features = serde_json::to_string(&vec![feature]).expect("encode feature list");
        let request = String::from_utf8(request_with_parameters("{}"))
            .expect("request UTF-8")
            .replace(
                "\"required_features\":[]",
                &format!("\"required_features\":{features}"),
            );
        assert_eq!(
            decode_job_request(request.as_bytes()).is_ok(),
            length == 128,
            "required feature character limit {length}"
        );
    }
    for count in [32, 33] {
        let features = (0..count)
            .map(|index| format!("feature-{index}"))
            .collect::<Vec<_>>();
        let encoded = serde_json::to_string(&features).expect("encode feature list");
        let request = String::from_utf8(request_with_parameters("{}"))
            .expect("request UTF-8")
            .replace(
                "\"required_features\":[]",
                &format!("\"required_features\":{encoded}"),
            );
        assert_eq!(
            decode_job_request(request.as_bytes()).is_ok(),
            count == 32,
            "required feature count limit {count}"
        );
    }

    let base = request_with_parameters(r#"{"padding":""}"#);
    let padding_length = 65_536 - base.len();
    let exact = request_with_parameters(&format!(
        r#"{{"padding":"{}"}}"#,
        "x".repeat(padding_length)
    ));
    assert_eq!(exact.len(), 65_536);
    assert!(decode_job_request(&exact).is_ok());
    let over = request_with_parameters(&format!(
        r#"{{"padding":"{}"}}"#,
        "x".repeat(padding_length + 1)
    ));
    assert!(decode_job_request(&over).is_err());

    let input = format!("{{\"input_id\":\"{INPUT_ID}\"}}");
    for count in [64, 65] {
        let values = std::iter::repeat_n(input.as_str(), count)
            .collect::<Vec<_>>()
            .join(",");
        let request = String::from_utf8(request_with_parameters("{}"))
            .expect("request UTF-8")
            .replace(
                &format!("\"inputs\":{{\"mesh\":[{input}]}}"),
                &format!("\"inputs\":{{\"mesh\":[{values}]}}"),
            );
        assert_eq!(
            decode_job_request(request.as_bytes()).is_ok(),
            count == 64,
            "aggregate input occurrence limit {count}"
        );
    }
    for count in [16, 17] {
        let roles = (0..count)
            .map(|index| format!("\"role{index}\":[{input}]"))
            .collect::<Vec<_>>()
            .join(",");
        let request = String::from_utf8(request_with_parameters("{}"))
            .expect("request UTF-8")
            .replace(
                &format!("\"inputs\":{{\"mesh\":[{input}]}}"),
                &format!("\"inputs\":{{{roles}}}"),
            );
        assert_eq!(
            decode_job_request(request.as_bytes()).is_ok(),
            count == 16,
            "input role count limit {count}"
        );
    }
    for length in [64, 65] {
        let role = format!("r{}", "a".repeat(length - 1));
        let request = String::from_utf8(request_with_parameters("{}"))
            .expect("request UTF-8")
            .replace("\"mesh\":", &format!("\"{role}\":"));
        assert_eq!(
            decode_job_request(request.as_bytes()).is_ok(),
            length == 64,
            "input role character limit {length}"
        );
    }
}
#[test]
fn bounded_record_decoder_honors_its_explicit_limit_without_changing_wire_request_limits() {
    let bytes = format!("{{\"body\":\"{}\"}}", "x".repeat(300_000)).into_bytes();
    assert!(
        dissect3d_api::decode_submission_json::<std::collections::BTreeMap<String, String>>(
            &bytes, 1_048_576
        )
        .is_ok()
    );
    assert!(
        dissect3d_api::decode_submission_json::<std::collections::BTreeMap<String, String>>(
            &bytes, 262_144
        )
        .is_err()
    );
    assert!(dissect3d_api::decode_job_request(&bytes).is_err());
}
