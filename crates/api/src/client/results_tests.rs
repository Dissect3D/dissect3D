use super::*;
use crate::{EnginePhase, PlatformInfo};
use std::collections::BTreeMap;

fn base_info(
    grants: Vec<&str>,
    result_publication: Option<ResultPublicationCapability>,
) -> EngineInfo {
    EngineInfo {
        api_version: "1.0".to_owned(),
        engine_version: "0.1.0-dev".to_owned(),
        installation_id: InstallationId::parse("ins_0123456789abcdef0123456789abcdef").unwrap(),
        instance_id: InstanceId::parse("eng_0123456789abcdef0123456789abcdef").unwrap(),
        phase: EnginePhase::Ready,
        supported_operations: vec!["engine.info".to_owned()],
        granted_operations: grants.into_iter().map(str::to_owned).collect(),
        required_features: Vec::new(),
        limits: BTreeMap::new(),
        limits_source: Some("built_in".to_owned()),
        platform: PlatformInfo {
            os: "linux".to_owned(),
            architecture: "x86_64".to_owned(),
        },
        discovery: None,
        submission: None,
        result_publication,
    }
}

fn capability() -> ResultPublicationCapability {
    ResultPublicationCapability {
        contract_version: "rp-0.1".to_owned(),
        operations: vec![
            "results.list".to_owned(),
            "results.show".to_owned(),
            "artifacts.read".to_owned(),
            "storage.show".to_owned(),
        ],
        limits: BTreeMap::from([("manifest_bytes_max".to_owned(), 262_144)]),
        required_features: vec![RESULT_FEATURE.to_owned()],
    }
}

#[test]
fn result_publication_capability_checks_contract_operation_and_grant() {
    let missing = base_info(vec!["results.list"], None);
    assert_eq!(
        validate_result_publication_capability(&missing, "results.list"),
        Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
    );

    let ungranted = base_info(vec!["engine.info"], Some(capability()));
    assert_eq!(
        validate_result_publication_capability(&ungranted, "results.list"),
        Err(ClientError::Rejected(ErrorCode::Forbidden))
    );

    let ok = base_info(
        vec![
            "results.list",
            "results.show",
            "artifacts.read",
            "storage.show",
        ],
        Some(capability()),
    );
    for op in [
        "results.list",
        "results.show",
        "artifacts.read",
        "storage.show",
    ] {
        assert_eq!(validate_result_publication_capability(&ok, op), Ok(()));
    }

    let mut wrong_contract = capability();
    wrong_contract.contract_version = "rp-0.2".to_owned();
    assert_eq!(
        validate_result_publication_capability(
            &base_info(vec!["results.list"], Some(wrong_contract)),
            "results.list"
        ),
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );

    let mut unknown_feature = capability();
    unknown_feature
        .required_features
        .push("result_publication.future".to_owned());
    assert_eq!(
        validate_result_publication_capability(
            &base_info(vec!["results.list"], Some(unknown_feature)),
            "results.list"
        ),
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );

    let mut missing_op = capability();
    missing_op.operations.retain(|op| op != "artifacts.read");
    assert_eq!(
        validate_result_publication_capability(
            &base_info(vec!["artifacts.read"], Some(missing_op)),
            "artifacts.read"
        ),
        Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
    );
}

#[test]
fn attachment_disposition_requires_attachment_and_extracts_filename() {
    assert_eq!(
        parse_attachment_disposition("attachment; filename=\"mesh.obj\""),
        Ok(Some("mesh.obj".to_owned()))
    );
    assert_eq!(parse_attachment_disposition("Attachment"), Ok(None));
    assert_eq!(
        parse_attachment_disposition("inline; filename=\"mesh.obj\""),
        Err(ClientError::InvalidResponse)
    );
}

#[test]
fn unsupported_manifest_feature_detection_distinguishes_incompatibility() {
    assert!(has_unsupported_manifest_feature(
        br#"{"manifest_version":"1.0","required_features":["result_publication.future"]}"#
    ));
    assert!(has_unsupported_manifest_feature(
        br#"{"manifest_version":"2.0","required_features":["result_publication.rp-0.1"]}"#
    ));
    assert!(!has_unsupported_manifest_feature(
        br#"{"manifest_version":"1.0","required_features":["result_publication.rp-0.1"]}"#
    ));
    assert!(!has_unsupported_manifest_feature(b"not-json"));
}
