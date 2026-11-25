//! Public HTTP + typed Client integration tests for `RP-P04` result/storage
//! capability advertisement, grant enforcement, and transport hardening.

#![cfg(unix)]

use dissect3d_api::{
    Client, ClientError, ClientId, ClientLimits, ConnectionMaterial, EnrollmentId, ErrorCode,
    RESULT_FEATURE, ResultsQuery, SecretToken, StorageMeasurementStatus, TokenDigest,
};
use dissect3d_engine::{CorePolicy, HttpServer, Store, VerifiedEnrollment, serve_bootstrap_once};
use dissect3d_platform::{
    AuthorityLease, BootstrapListener, OwnedRoot, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::oneshot;

const CORE_CLIENT: &str = "cli_11111111111111111111111111111111";
const EXEC_CLIENT: &str = "cli_22222222222222222222222222222222";
const CORE_SECRET: [u8; 32] = [0x41; 32];
const EXEC_SECRET: [u8; 32] = [0x42; 32];

#[tokio::test]
async fn info_advertises_result_publication_and_enforces_grants_and_transport_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = std::sync::Arc::new(Store::open(root, lease, &CorePolicy::default()).unwrap());
    let http_root = OwnedRoot::open(&path, RootPurpose::EngineData).unwrap();
    let identity = store.identity().unwrap();

    // Enroll a CoreV1 client (lacking results.*/artifacts.read/storage.show).
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().unwrap(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse("enr_11111111111111111111111111111111").unwrap(),
            ClientId::parse(CORE_CLIENT).unwrap(),
            TokenDigest::new(Sha256::digest(CORE_SECRET).into()),
        ))
        .unwrap();

    // Enroll an ExecutionV1 client through native bootstrap.
    let secret_hex: String = EXEC_SECRET.iter().map(|b| format!("{b:02x}")).collect();
    let message = json!({
        "kind": "enroll_execution",
        "bootstrap_version": "1.0",
        "installation_id": identity.installation_id,
        "instance_id": identity.instance_id,
        "client_id": EXEC_CLIENT,
        "enrollment_id": "enr_22222222222222222222222222222222",
        "client_kind": "cli",
        "secret_hex": secret_hex,
        "execution_contract": "execution-v1",
    });
    let listener = BootstrapListener::bind(&http_root, identity.instance_id.as_str()).unwrap();
    let endpoint = listener.endpoint().clone();
    let owner = current_owner_identity().unwrap();
    let boot_store = store.clone();
    let boot_thread = std::thread::spawn(move || {
        serve_bootstrap_once(&listener, &boot_store, Duration::from_secs(5)).unwrap();
    });
    let mut channel = connect_bootstrap(&endpoint, &owner, Duration::from_secs(5)).unwrap();
    channel
        .write_frame(&serde_json::to_vec(&message).unwrap())
        .unwrap();
    let reply: Value = serde_json::from_slice(&channel.read_frame().unwrap()).unwrap();
    assert_eq!(reply["client_id"], EXEC_CLIENT);
    drop(channel);
    boot_thread.join().unwrap();

    let server = HttpServer::bind(&http_root, store.clone(), CorePolicy::default())
        .await
        .unwrap();
    let base_url = server.base_url();
    let (ca_der, ca_sha256) = server.trust_anchor();
    let ca_der = ca_der.to_vec();
    let ca_sha256 = *ca_sha256;
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = server.run(stop_rx).await;
    });

    let make_client = |client_id: &str, secret: [u8; 32]| {
        Client::new(
            ConnectionMaterial::new(
                format!("{base_url}/"),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                ClientId::parse(client_id).unwrap(),
                ca_der.clone(),
                ca_sha256,
                SecretToken::new(secret.to_vec()).unwrap(),
            ),
            ClientLimits::default(),
        )
        .unwrap()
    };

    let core_client = make_client(CORE_CLIENT, CORE_SECRET);
    let exec_client = make_client(EXEC_CLIENT, EXEC_SECRET);

    // /v1/info advertises result_publication capability.
    let info = exec_client.info().await.unwrap();
    let cap = info
        .result_publication
        .expect("Unix host advertises result_publication");
    assert_eq!(cap.contract_version, "rp-0.1");
    assert_eq!(cap.required_features, vec![RESULT_FEATURE]);
    for op in [
        "results.list",
        "results.show",
        "artifacts.read",
        "storage.show",
    ] {
        assert!(cap.operations.iter().any(|item| item == op), "{op}");
        assert!(
            info.supported_operations.iter().any(|item| item == op),
            "{op}"
        );
    }

    // CoreV1 client is denied with Forbidden on all 4 operations.
    assert_eq!(
        core_client.results(ResultsQuery::default()).await.err(),
        Some(ClientError::Rejected(ErrorCode::Forbidden))
    );
    assert_eq!(
        core_client
            .result_manifest("res_11111111111111111111111111111111")
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::Forbidden))
    );
    assert_eq!(
        core_client
            .artifact("art_11111111111111111111111111111111", 1024)
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::Forbidden))
    );
    assert_eq!(
        core_client.storage().await.err(),
        Some(ClientError::Rejected(ErrorCode::Forbidden))
    );

    // ExecutionV1 client can list empty results, read storage, and gets 404 on unknown IDs.
    let empty = exec_client.results(ResultsQuery::default()).await.unwrap();
    assert!(empty.items.is_empty());
    assert!(!empty.truncated);
    assert!(empty.next_cursor.is_none());

    let storage = exec_client.storage().await.unwrap();
    assert_eq!(storage.api_version, "1.0");
    assert_eq!(storage.storage_contract, "rp-0.1");
    assert_eq!(
        storage.measurement.status,
        StorageMeasurementStatus::Current
    );
    assert_eq!(storage.usage.published_output_bytes, Some(0));

    assert_eq!(
        exec_client
            .result_manifest("res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::NotFound))
    );
    assert_eq!(
        exec_client
            .artifact("art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1024)
            .await
            .err(),
        Some(ClientError::Rejected(ErrorCode::NotFound))
    );

    // Origin header is denied on result/storage routes.
    let raw = reqwest::Client::builder()
        .https_only(true)
        .tls_backend_rustls()
        .tls_certs_only([reqwest::Certificate::from_der(&ca_der).unwrap()])
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .build()
        .unwrap();
    let bearer = format!("Bearer {EXEC_CLIENT}.{secret_hex}");
    for path in [
        "/v1/results",
        "/v1/results/res_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/manifest",
        "/v1/artifacts/art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/v1/storage",
    ] {
        let resp = raw
            .get(format!("{base_url}{path}"))
            .header("Authorization", &bearer)
            .header("Origin", "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{path}");
    }

    let _ = stop_tx.send(());
    let _ = task.await;
}
