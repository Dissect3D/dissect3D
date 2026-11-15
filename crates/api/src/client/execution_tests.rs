use super::execution::validate_execution_capability;
use super::*;
use crate::{ExecutionCapability, ExecutionRecord};

fn info() -> crate::ExecutionEngineInfo {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/execution-info.json")).unwrap();
    value["job_execution"] = serde_json::json!({"contract_version":"we-0.1","dispatch_enabled":true,"operations":["jobs.submit","jobs.list","jobs.show","jobs.cancel","jobs.retry","inputs.create"],"limits":{"execution_timeout_ms_max":86400000},"required_features":[]});
    value["submission"] = serde_json::to_value(SubmissionCapability {
        version: "1.0".into(),
        dispatch_enabled: true,
        operations: SUBMISSION_OPERATIONS.iter().map(|s| (*s).into()).collect(),
        limits: REQUIRED_SUBMISSION_LIMITS
            .iter()
            .map(|(k, v)| ((*k).into(), *v))
            .collect(),
        limits_source: "engine".into(),
    })
    .unwrap();
    value["granted_operations"] = serde_json::json!([
        "jobs.submit",
        "jobs.list",
        "jobs.show",
        "jobs.cancel",
        "jobs.retry",
        "inputs.create"
    ]);
    serde_json::from_value(value).unwrap()
}

#[test]
fn negotiation_rejects_missing_capability_unknown_semantics_and_inconsistent_dispatch() {
    let good = info();
    assert!(validate_execution_capability(&good, "jobs.submit").is_ok());
    let mut known = good.clone();
    known
        .job_execution
        .as_mut()
        .unwrap()
        .required_features
        .push(crate::EXECUTION_FEATURE.into());
    assert!(validate_execution_capability(&known, "jobs.submit").is_ok());
    assert_eq!(
        validate_submission_capability(
            &good.core.granted_operations,
            good.core.submission.as_ref(),
            "jobs.list"
        ),
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );
    assert_eq!(
        validate_submission_capability(
            &good.core.granted_operations,
            good.core.submission.as_ref(),
            "jobs.show"
        ),
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );
    let mut missing = good.clone();
    missing.job_execution = None;
    assert_eq!(
        validate_execution_capability(&missing, "jobs.submit"),
        Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
    );
    let mut unknown = good.clone();
    unknown
        .job_execution
        .as_mut()
        .unwrap()
        .required_features
        .push("unknown".into());
    assert!(validate_execution_capability(&unknown, "inputs.create").is_err());
    let mut inconsistent = good.clone();
    inconsistent
        .core
        .submission
        .as_mut()
        .unwrap()
        .dispatch_enabled = false;
    assert!(validate_execution_capability(&inconsistent, "jobs.submit").is_err());
    let mut forbidden = good.clone();
    forbidden.core.granted_operations.clear();
    assert_eq!(
        validate_execution_capability(&forbidden, "jobs.cancel"),
        Err(ClientError::Rejected(ErrorCode::Forbidden))
    );
    let mut version = good;
    version.job_execution.as_mut().unwrap().contract_version = "we-9".into();
    assert!(validate_execution_capability(&version, "jobs.submit").is_err());
    let capability:ExecutionCapability=serde_json::from_str(r#"{"contract_version":"we-0.1","dispatch_enabled":false,"operations":[],"limits":{"x":1},"required_features":[]}"#).unwrap();
    assert!(capability.validate().is_ok());
}
