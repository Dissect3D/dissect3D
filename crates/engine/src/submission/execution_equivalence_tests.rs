use super::*;
use dissect3d_api::decode_execution_request;

#[test]
fn v2_policy_conflicts_and_v1_identity_are_separate() {
    let legacy = br#"{"api_version":"1.0","support_ref":"copy","task":{"id":"copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_11111111111111111111111111111111"}]},"parameters":{},"required_features":[],"evaluation_consent":false}"#;
    let mut inputs = VerifiedInputMap::new();
    inputs.insert(
        "inp_11111111111111111111111111111111".into(),
        InputIdentity {
            input_id: dissect3d_api::InputId::parse("inp_11111111111111111111111111111111")
                .unwrap(),
            media_type: "application/octet-stream".into(),
            byte_length: 4,
            sha256: dissect3d_api::ContentDigest::parse(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
        },
    );
    let old = dissect3d_api::decode_job_request(legacy).unwrap();
    let old_identity = canonicalize(&old, &inputs).unwrap();
    let text = String::from_utf8(legacy.to_vec()).unwrap().replace(
        "\"required_features\":[]",
        "\"required_features\":[\"job_execution.we-0.1\"]",
    );
    let none = decode_execution_request(text.as_bytes()).unwrap();
    let empty = decode_execution_request(
        text.replace("\"parameters\":{}", "\"parameters\":{},\"execution\":{}")
            .as_bytes(),
    )
    .unwrap();
    let deadline = decode_execution_request(
        text.replace(
            "\"parameters\":{}",
            "\"parameters\":{},\"execution\":{\"timeout_ms\":1}",
        )
        .as_bytes(),
    )
    .unwrap();
    let v2 = canonicalize_execution(&none, &inputs).unwrap();
    assert_eq!(v2, canonicalize_execution(&empty, &inputs).unwrap());
    assert_ne!(
        v2.fingerprint,
        canonicalize_execution(&deadline, &inputs)
            .unwrap()
            .fingerprint
    );
    assert_ne!(v2.fingerprint, old_identity.fingerprint);
    assert_eq!(v2.version.as_i64(), 2);
    assert_eq!(old_identity.version.as_i64(), 1);
    assert_eq!(old_identity, canonicalize(&old, &inputs).unwrap());
    let expected = br#"["object",[["api_version","1.0"],["evaluation_consent",false],["execution",["object",[]]],["inputs",["object",[["mesh",["array",[["object",[["byte_length",["integer","4"]],["media_type","application/octet-stream"],["sha256","aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]]]]]]]],["parameters",["object",[]]],["required_features",["array",["job_execution.we-0.1"]]],["support_ref","copy"],["task",["object",[["id","copy"],["version","1.0"]]]]]]"#;
    assert_eq!(v2.bytes, expected);
    assert_eq!(
        v2.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "531c0944946fb60589c9cfafc7e35eb79077ffd98125aefd606ff61959c9b463"
    );
}
