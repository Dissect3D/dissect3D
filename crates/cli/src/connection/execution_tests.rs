use super::*;
fn binding() -> (InstallationId, ClientId) {
    (
        InstallationId::parse("ins_11111111111111111111111111111111").unwrap(),
        ClientId::parse("cli_22222222222222222222222222222222").unwrap(),
    )
}
pub(super) fn credential(
    installation: &InstallationId,
    client: &ClientId,
    state: &str,
) -> ProfileCredential {
    ProfileCredential {
        installation_id: installation.clone(),
        instance_id: InstanceId::parse("eng_33333333333333333333333333333333").unwrap(),
        client_id: client.clone(),
        enrollment_id: EnrollmentId::parse("enr_44444444444444444444444444444444").unwrap(),
        secret_hex: if state == "revoked" {
            String::new()
        } else {
            "5".repeat(64)
        },
        state: state.into(),
        submission_access: false,
    }
}
#[cfg(unix)]
#[test]
fn authorization_record_survives_reload_and_success_without_touching_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("profile.json");
    let profile = Profile::open(&path).unwrap();
    let (installation, client) = binding();
    let lease = profile.control_lease().unwrap();
    let pending = profile
        .begin_execution_authorization(&lease, &credential(&installation, &client, "active"))
        .unwrap();
    assert_eq!(pending.state, "pending");
    let again = profile
        .begin_execution_authorization(&lease, &credential(&installation, &client, "active"))
        .unwrap();
    assert_eq!(pending.authorization_id, again.authorization_id);
    assert!(profile.load().unwrap().is_none());
    let receipt = dissect3d_api::ExecutionAuthorizationReceipt {
        bootstrap_version: "1.0".into(),
        contract_version: "execution-v1".into(),
        installation_id: installation.clone(),
        client_id: client.clone(),
        authorization_id: pending.authorization_id.clone(),
        grant_policy: "execution-v1".into(),
        granted_operations: dissect3d_api::EXECUTION_GRANTS
            .iter()
            .map(|s| (*s).into())
            .collect(),
        replayed: true,
    };
    profile
        .complete_execution_authorization(&lease, &receipt)
        .unwrap();
    let complete = profile
        .begin_execution_authorization(&lease, &credential(&installation, &client, "active"))
        .unwrap();
    assert_eq!(complete.state, "complete");
    assert_eq!(complete.authorization_id, pending.authorization_id);
    // 2026-11-17 confirmed rule D: only a non-active credential for another
    // client is refused; an active one supersedes (see recovery tests).
    let wrong = ClientId::parse("cli_33333333333333333333333333333333").unwrap();
    for state in ["pending", "revoked"] {
        assert!(matches!(
            profile
                .begin_execution_authorization(&lease, &credential(&installation, &wrong, state)),
            Err(ConnectionError::Conflict)
        ));
    }
}
#[cfg(windows)]
#[test]
fn windows_authorization_pending_is_refused_before_any_record_write() {
    let temp = tempfile::tempdir().unwrap();
    let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
    let (installation, client) = binding();
    let lease = profile.control_lease().unwrap();
    assert!(matches!(
        profile
            .begin_execution_authorization(&lease, &credential(&installation, &client, "active")),
        Err(ConnectionError::Incompatible)
    ));
    let file = RelativePath::parse("execution-authorization.json").unwrap();
    assert!(matches!(
        profile.root.read_file(&file, 4096),
        Err(PlatformError::NotFound)
    ));
}
#[test]
fn native_authorization_receipt_rejects_partial_or_substituted_grants() {
    let (installation, client) = binding();
    let mut value = serde_json::json!({"bootstrap_version":"1.0","contract_version":"execution-v1","installation_id":installation,"client_id":client,"authorization_id":"aut_33333333333333333333333333333333","grant_policy":"execution-v1","granted_operations":["jobs.submit"],"replayed":true});
    assert!(decode_execution_authorization_receipt(&serde_json::to_vec(&value).unwrap()).is_err());
    value["granted_operations"] = serde_json::json!(dissect3d_api::EXECUTION_GRANTS);
    assert!(decode_execution_authorization_receipt(&serde_json::to_vec(&value).unwrap()).is_ok());
}
