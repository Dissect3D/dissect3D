use super::{Request, RequestError, Response, process_request};
use crate::{CorePolicy, Store};
use dissect3d_api::{ClientId, EnrollmentId};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RootPurpose, current_owner_identity};
use serde_json::{Value, json};
use tempfile::tempdir;

fn test_store() -> (tempfile::TempDir, Store, crate::StoreIdentity) {
    let directory = tempdir().expect("temporary root");
    let root_path = directory.path().join("engine-root");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority lease");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
    let identity = store.identity().expect("store identity");
    (directory, store, identity)
}

fn value(response: Response) -> Value {
    serde_json::to_value(response).expect("bootstrap response JSON")
}

#[test]
fn capabilities_are_separate_and_the_probe_receipt_stays_unchanged() {
    let (_directory, store, identity) = test_store();
    let owner = current_owner_identity().expect("owner identity");
    let probe = process_request(
        Request::Probe {
            bootstrap_version: "1.0".to_owned(),
            instance_id: identity.instance_id.clone(),
        },
        &store,
        owner.clone(),
    )
    .expect("old probe");
    assert_eq!(
        value(probe),
        json!({
            "bootstrap_version": "1.0",
            "installation_id": identity.installation_id,
            "instance_id": identity.instance_id,
            "ready": true
        })
    );

    let capabilities = process_request(
        Request::Capabilities {
            bootstrap_version: "1.0".to_owned(),
            instance_id: identity.instance_id.clone(),
        },
        &store,
        owner,
    )
    .expect("native capability exchange");
    assert_eq!(
        value(capabilities),
        json!({
            "bootstrap_version": "1.0",
            "installation_id": identity.installation_id,
            "instance_id": identity.instance_id,
            "enrollment_policies": ["core-v1", "submission-v1"]
        })
    );
}

#[test]
fn opt_in_enrollment_is_closed_and_replays_the_same_policy() {
    let (_directory, store, identity) = test_store();
    let owner = current_owner_identity().expect("owner identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap();
    let enrollment_id = EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap();
    let secret_hex = "ab".repeat(32);
    let request = || Request::EnrollSubmission {
        bootstrap_version: "1.0".to_owned(),
        installation_id: identity.installation_id.clone(),
        instance_id: identity.instance_id.clone(),
        enrollment_id: enrollment_id.clone(),
        client_id: client_id.clone(),
        client_kind: "cli".to_owned(),
        secret_hex: super::SecretHex(secret_hex.as_bytes().to_vec()),
    };
    let first =
        value(process_request(request(), &store, owner.clone()).expect("submission enrollment"));
    assert_eq!(first["replayed"], false);
    assert_eq!(
        first["granted_operations"],
        json!([
            "auth.revoke_self",
            "auth.status",
            "engine.info",
            "engine.shutdown",
            "inputs.create",
            "jobs.list",
            "jobs.show",
            "jobs.submit",
            "operation.show_own"
        ])
    );
    let replay =
        value(process_request(request(), &store, owner.clone()).expect("lost-receipt replay"));
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["granted_operations"], first["granted_operations"]);

    let conflicting_core_request = Request::Enroll {
        bootstrap_version: "1.0".to_owned(),
        installation_id: identity.installation_id.clone(),
        instance_id: identity.instance_id.clone(),
        enrollment_id: enrollment_id.clone(),
        client_id: client_id.clone(),
        client_kind: "cli".to_owned(),
        secret_hex: super::SecretHex(secret_hex.as_bytes().to_vec()),
    };
    assert!(matches!(
        process_request(conflicting_core_request, &store, owner),
        Err(RequestError::Conflict)
    ));

    let caller_selected_grants = br#"{"kind":"enroll_submission","bootstrap_version":"1.0","installation_id":"ins_0123456789abcdef0123456789abcdef","instance_id":"eng_0123456789abcdef0123456789abcdef","enrollment_id":"enr_0123456789abcdef0123456789abcdef","client_id":"cli_0123456789abcdef0123456789abcdef","client_kind":"cli","secret_hex":"abababababababababababababababababababababababababababababababab","granted_operations":["jobs.submit"]}"#;
    assert!(dissect3d_api::decode_json::<Request>(caller_selected_grants).is_err());
}
