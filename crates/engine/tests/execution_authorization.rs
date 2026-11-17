//! Real native peer/channel regressions; no worker execution is activated.
use dissect3d_api::{ClientId, TokenDigest};
use dissect3d_engine::{CorePolicy, Store, serve_bootstrap_once};
use dissect3d_platform::{
    AuthorityLease, BootstrapListener, OwnedRoot, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
#[cfg(unix)]
const EXPECTED_EXECUTION_GRANTS: [&str; 15] = [
    "artifacts.read",
    "auth.revoke_self",
    "auth.status",
    "engine.info",
    "engine.shutdown",
    "inputs.create",
    "jobs.cancel",
    "jobs.list",
    "jobs.retry",
    "jobs.show",
    "jobs.submit",
    "operation.show_own",
    "results.list",
    "results.show",
    "storage.show",
];
const CLIENT: &str = "cli_11111111111111111111111111111111";
const ENROLLMENT: &str = "enr_22222222222222222222222222222222";
fn start(path: &Path) -> Arc<Store> {
    let root = OwnedRoot::create_private(path, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    Arc::new(Store::open(root, lease, &CorePolicy::default()).unwrap())
}
fn message(store: &Store, kind: &str) -> Value {
    let id = store.identity().unwrap();
    let mut value = json!({"kind":kind,"bootstrap_version":"1.0","installation_id":id.installation_id,"instance_id":id.instance_id,"client_id":CLIENT,"secret_hex":"35".repeat(32)});
    match kind {
        "execution_capabilities" => {
            value = json!({"kind":kind,"bootstrap_version":"1.0","instance_id":id.instance_id});
        }
        "authorize_execution" => {
            value["execution_contract"] = json!("execution-v1");
            value["authorization_id"] = json!("aut_33333333333333333333333333333333");
        }
        _ => {
            value["enrollment_id"] = json!(ENROLLMENT);
            value["client_kind"] = json!("cli");
            if kind == "enroll_execution" {
                value["execution_contract"] = json!("execution-v1");
            }
        }
    };
    value
}
fn exchange(path: &Path, store: &Arc<Store>, message: Value, abandon: bool) -> Option<Value> {
    let root = OwnedRoot::open(path, RootPurpose::EngineData).unwrap();
    let listener =
        BootstrapListener::bind(&root, store.identity().unwrap().instance_id.as_str()).unwrap();
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().unwrap();
    let server_store = store.clone();
    let thread = std::thread::spawn(move || {
        serve_bootstrap_once(&listener, &server_store, Duration::from_secs(5))
    });
    let mut channel = connect_bootstrap(&endpoint, &owner, Duration::from_secs(5)).unwrap();
    channel
        .write_frame(&serde_json::to_vec(&message).unwrap())
        .unwrap();
    let result = if abandon {
        None
    } else {
        Some(serde_json::from_slice(&channel.read_frame().unwrap()).unwrap())
    };
    drop(channel);
    let served = thread.join().unwrap();
    if !abandon {
        served.unwrap();
    }
    store.identity().unwrap();
    result
}
#[cfg(unix)]
fn context(store: &Store) -> dissect3d_engine::AuthContext {
    store
        .authenticate(
            ClientId::parse(CLIENT).unwrap(),
            TokenDigest::new(Sha256::digest([0x35; 32]).into()),
        )
        .unwrap()
}

#[cfg(unix)]
#[test]
fn execution_enrollment_is_atomic_repeat_safe_after_restart_and_preserves_old_receipt_policy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    let mut store = start(&path);
    let capability = exchange(
        &path,
        &store,
        message(&store, "execution_capabilities"),
        false,
    )
    .unwrap();
    assert_eq!(capability["contract_version"], "execution-v1");
    let request = message(&store, "enroll_execution");
    exchange(&path, &store, request.clone(), true);
    assert_eq!(context(&store).granted_operations().len(), 15);
    let first = exchange(&path, &store, request, false).unwrap();
    assert_eq!(first["replayed"], true);
    assert_eq!(
        first["granted_operations"],
        json!(EXPECTED_EXECUTION_GRANTS)
    );
    drop(store);
    store = start(&path);
    let replay = exchange(&path, &store, message(&store, "enroll_execution"), false).unwrap();
    assert_eq!(replay["client_id"], CLIENT);
    assert_eq!(replay["enrollment_id"], ENROLLMENT);
    assert_eq!(replay["replayed"], true);
    let legacy = exchange(&path, &store, message(&store, "enroll_submission"), false).unwrap();
    assert_eq!(legacy["error"], "conflict");
    assert_eq!(context(&store).granted_operations().len(), 15);
    store.revoke_self(context(&store)).unwrap();
    let denied = exchange(&path, &store, message(&store, "enroll_execution"), false).unwrap();
    assert_eq!(denied["error"], "unauthorized");
}
#[cfg(unix)]
#[test]
fn same_client_authorization_recovers_lost_ack_without_secret_rotation_or_revoked_revival() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    let mut store = start(&path);
    let original = exchange(&path, &store, message(&store, "enroll"), false).unwrap();
    assert_eq!(original["granted_operations"].as_array().unwrap().len(), 5);
    let mut wrong = message(&store, "authorize_execution");
    wrong["secret_hex"] = json!("36".repeat(32));
    assert_eq!(
        exchange(&path, &store, wrong, false).unwrap()["error"],
        "unauthorized"
    );
    let request = message(&store, "authorize_execution");
    exchange(&path, &store, request.clone(), true);
    assert_eq!(context(&store).granted_operations().len(), 15);
    let replay = exchange(&path, &store, request, false).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["client_id"], CLIENT);
    drop(store);
    store = start(&path);
    assert_eq!(
        exchange(&path, &store, message(&store, "authorize_execution"), false).unwrap()["replayed"],
        true
    );
    let legacy = exchange(&path, &store, message(&store, "enroll"), false).unwrap();
    assert_eq!(legacy["granted_operations"], original["granted_operations"]);
    store.revoke_self(context(&store)).unwrap();
    assert_eq!(
        exchange(&path, &store, message(&store, "authorize_execution"), false).unwrap()["error"],
        "unauthorized"
    );
}
#[cfg(windows)]
#[test]
fn windows_execution_capability_and_both_mutations_remain_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    let store = start(&path);
    for kind in [
        "execution_capabilities",
        "enroll_execution",
        "authorize_execution",
    ] {
        let reply = exchange(&path, &store, message(&store, kind), false).unwrap();
        assert!(reply.get("error").is_some(), "{kind}");
    }
    assert!(
        store
            .authenticate(
                ClientId::parse(CLIENT).unwrap(),
                TokenDigest::new(Sha256::digest([0x35; 32]).into())
            )
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn unknown_execution_contract_or_members_reject_before_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    let store = start(&path);
    for wrong in ["contract", "member"] {
        let mut request = message(&store, "enroll_execution");
        if wrong == "contract" {
            request["execution_contract"] = json!("future-v9");
        } else {
            request["granted_operations"] = json!(["jobs.submit"]);
        }
        assert_eq!(
            exchange(&path, &store, request, false).unwrap()["error"],
            "invalid_request"
        );
    }
    assert!(
        store
            .authenticate(
                ClientId::parse(CLIENT).unwrap(),
                TokenDigest::new(Sha256::digest([0x35; 32]).into())
            )
            .is_err()
    );
}
