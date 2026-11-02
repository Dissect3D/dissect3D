use dissect3d_api::{
    ApiError, AuthStatus, Client, ClientError, ClientId, ClientLimits, ConnectionMaterial,
    EnrollmentId, ErrorCode, IdempotencyKey, OperationReceipt, OperationSnapshot, OperationTarget,
    SecretToken, ShutdownOptions, ShutdownRequest, TokenDigest, decode_json,
};
use dissect3d_engine::{CorePolicy, HttpServer, Store, VerifiedEnrollment};
use dissect3d_platform::{
    AuthorityLease, OwnedRoot, RelativePath, RootPurpose, current_owner_identity,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};

const CLIENT_ID: &str = "cli_0123456789abcdef0123456789abcdef";
const ENROLLMENT_ID: &str = "enr_0123456789abcdef0123456789abcdef";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_https_checks_trust_host_origin_auth_and_revocation() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID).expect("client identity");
    let secret = [42_u8; 32];
    let digest: [u8; 32] = Sha256::digest(secret).into();
    let receipt = store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse(ENROLLMENT_ID).expect("enrollment identity"),
            client_id.clone(),
            TokenDigest::new(digest),
        ))
        .expect("durable credential");
    assert_eq!(receipt.client_id, client_id);

    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.base_url();
    let (ca_der, ca_sha256) = server.trust_anchor();
    let ca_der = ca_der.to_vec();
    let ca_sha256 = *ca_sha256;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));

    let client = Client::new(
        ConnectionMaterial::new(
            endpoint.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            client_id.clone(),
            ca_der.clone(),
            ca_sha256,
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        Default::default(),
    )
    .expect("trusted HTTPS client");
    let info = client.info().await.expect("authenticated engine info");
    assert_eq!(info.installation_id, identity.installation_id);
    assert_eq!(info.instance_id, identity.instance_id);
    assert_eq!(info.limits["control_response_bytes"], 262_144);
    assert_eq!(info.limits["http_connections"], 32);
    assert_eq!(info.limits["request_timeout_ms"], 5_000);
    assert!(
        serde_json::to_vec(&info)
            .expect("encoded engine info")
            .len()
            <= 262_144
    );
    let request_path = RelativePath::parse("run/requests.json").expect("request diagnostics path");
    let request_log = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(bytes) = tls_root.read_file(&request_path, 1_048_576) {
                break bytes;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("correlated request diagnostics");
    let request_records: Vec<serde_json::Value> =
        decode_json(&request_log).expect("strict request records");
    assert_eq!(request_records[0]["route"], "info");
    assert_eq!(request_records[0]["method"], "get");
    assert_eq!(request_records[0]["status"], 200);
    assert!(request_records[0]["correlation_id"].as_str().is_some());
    assert!(
        info.supported_operations
            .contains(&"engine.info".to_owned())
    );
    assert!(
        info.supported_operations
            .contains(&"engine.shutdown".to_owned())
    );
    assert!(
        info.supported_operations
            .contains(&"operation.show_own".to_owned())
    );
    let status: AuthStatus = client.auth_status().await.expect("authenticated status");
    assert!(status.active);
    assert_eq!(status.client_id, client_id);
    assert!(
        status
            .granted_operations
            .contains(&"operation.show_own".to_owned())
    );
    assert!(
        status
            .granted_operations
            .contains(&"engine.shutdown".to_owned())
    );

    let too_small = Client::new(
        ConnectionMaterial::new(
            endpoint.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            client_id.clone(),
            ca_der.clone(),
            ca_sha256,
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        ClientLimits {
            max_response_bytes: 1,
            ..Default::default()
        },
    )
    .expect("bounded API client");
    assert_eq!(too_small.info().await, Err(ClientError::TransferLimit));
    assert_eq!(ClientLimits::default().max_response_bytes, 262_144);
    assert!(matches!(
        Client::new(
            ConnectionMaterial::new(
                endpoint.clone(),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                client_id.clone(),
                ca_der.clone(),
                ca_sha256,
                SecretToken::new(secret.to_vec()).expect("secret"),
            ),
            ClientLimits {
                max_response_bytes: 262_145,
                ..Default::default()
            },
        ),
        Err(ClientError::InvalidMaterial)
    ));

    let other_ca = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("unrelated trust fixture");
    let other_der = other_ca.cert.der().to_vec();
    let other_pin: [u8; 32] = Sha256::digest(&other_der).into();
    let wrong_trust = Client::new(
        ConnectionMaterial::new(
            endpoint.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            client_id.clone(),
            other_der,
            other_pin,
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        Default::default(),
    )
    .expect("client with unrelated but valid trust anchor");
    assert_eq!(wrong_trust.info().await, Err(ClientError::Transport));

    let wrong_instance = Client::new(
        ConnectionMaterial::new(
            endpoint.clone(),
            identity.installation_id.clone(),
            dissect3d_api::InstanceId::parse("eng_ffffffffffffffffffffffffffffffff".to_owned())
                .expect("different expected instance"),
            client_id.clone(),
            ca_der.clone(),
            ca_sha256,
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        Default::default(),
    )
    .expect("client bound to another expected instance");
    assert_eq!(wrong_instance.info().await, Err(ClientError::Incompatible));

    // A client pinned to the discovered CA but without a bearer is rejected.
    let direct = reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([reqwest::Certificate::from_der(&ca_der).expect("CA certificate")])
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test HTTPS client");
    let missing = direct
        .get(format!("{endpoint}/v1/info"))
        .send()
        .await
        .expect("missing bearer response");
    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);

    let wrong_credential = direct
        .get(format!("{endpoint}/v1/info"))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {CLIENT_ID}.{}", "2b".repeat(32)),
        )
        .send()
        .await
        .expect("wrong credential response");
    assert_eq!(wrong_credential.status(), reqwest::StatusCode::UNAUTHORIZED);

    let wrong_host = direct
        .get(format!("{endpoint}/v1/info"))
        .header(reqwest::header::HOST, "127.0.0.1:1")
        .send()
        .await
        .expect("wrong Host response");
    assert_eq!(wrong_host.status(), reqwest::StatusCode::FORBIDDEN);
    let wrong_host_body = wrong_host.bytes().await.expect("safe Host error");
    let error: ApiError = decode_json(&wrong_host_body).expect("strict Host error");
    assert_eq!(error.error.code, ErrorCode::HostDenied);

    for value in ["null", "https://127.0.0.1", "https://untrusted.example"] {
        let origin = direct
            .get(format!("{endpoint}/v1/info"))
            .header(reqwest::header::ORIGIN, value)
            .send()
            .await
            .expect("Origin denial");
        assert_eq!(origin.status(), reqwest::StatusCode::FORBIDDEN);
        let origin_body = origin.bytes().await.expect("safe Origin error");
        let error: ApiError = decode_json(&origin_body).expect("strict Origin error");
        assert_eq!(error.error.code, ErrorCode::OriginDenied);
    }

    // The builder rejects a mismatched CA pin before creating any transport.
    let wrong_pin = Client::new(
        ConnectionMaterial::new(
            endpoint,
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            client_id,
            ca_der,
            [0; 32],
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        Default::default(),
    );
    assert_eq!(wrong_pin.err(), Some(ClientError::InvalidMaterial));

    let revoked = client.revoke_self().await.expect("durable self revocation");
    assert!(revoked.revoked);
    assert_eq!(
        client.auth_status().await,
        Err(ClientError::Rejected(ErrorCode::Unauthorized))
    );
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("server task join")
        .expect("server stopped");
    drop(store);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_rejects_duplicate_and_unknown_revoke_members_before_commit() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID).expect("client identity");
    let secret = [42_u8; 32];
    let digest = Sha256::digest(secret);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse(ENROLLMENT_ID).expect("enrollment identity"),
            client_id.clone(),
            TokenDigest::new(digest_bytes),
        ))
        .expect("durable credential");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.base_url();
    let (ca_der, ca_pin) = server.trust_anchor();
    let ca_pin_length = ca_pin.len();
    let auth = format!("Bearer {CLIENT_ID}.{}", "2a".repeat(32));
    let direct = reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([reqwest::Certificate::from_der(ca_der).expect("CA certificate")])
        .no_proxy()
        .build()
        .expect("test HTTPS client");
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));
    for body in [
        r#"{"api_version":"1.0","required_features":[],"required_features":[]}"#,
        r#"{"api_version":"1.0","required_features":[],"arbitrary":true}"#,
    ] {
        let response = direct
            .post(format!("{endpoint}/v1/auth/revoke"))
            .header(reqwest::header::AUTHORIZATION, &auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .expect("invalid body response");
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let bytes = response.bytes().await.expect("safe invalid-body error");
        let error: ApiError = decode_json(&bytes).expect("strict API error");
        assert_eq!(error.error.code, ErrorCode::InvalidRequest);
    }
    let oversized = direct
        .post(format!("{endpoint}/v1/auth/revoke"))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(vec![b' '; 65_537])
        .send()
        .await
        .expect("bounded request body response");
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let oversized_body = oversized.bytes().await.expect("safe transfer limit");
    let error: ApiError = decode_json(&oversized_body).expect("strict transfer error");
    assert_eq!(error.error.code, ErrorCode::TransferLimit);
    assert!(
        store
            .authenticate(client_id, TokenDigest::new(digest_bytes))
            .is_ok()
    );
    assert_eq!(ca_pin_length, 32);
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("server task join")
        .expect("server stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_rejects_wrong_method_version_and_required_features_without_revoking() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID).expect("client identity");
    let secret = [42_u8; 32];
    let digest = Sha256::digest(secret);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse(ENROLLMENT_ID).expect("enrollment identity"),
            client_id.clone(),
            TokenDigest::new(digest_bytes),
        ))
        .expect("durable credential");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.base_url();
    let (ca_der, ca_pin) = server.trust_anchor();
    let ca_pin_length = ca_pin.len();
    let direct = reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([reqwest::Certificate::from_der(ca_der).expect("CA certificate")])
        .no_proxy()
        .build()
        .expect("test HTTPS client");
    let auth = format!("Bearer {CLIENT_ID}.{}", "2a".repeat(32));
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));

    let wrong_method = direct
        .put(format!("{endpoint}/v1/auth/revoke"))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(r#"{"api_version":"1.0","required_features":[]}"#)
        .send()
        .await
        .expect("unsupported method response");
    assert_eq!(
        wrong_method.status(),
        reqwest::StatusCode::METHOD_NOT_ALLOWED
    );

    let old_http_version = direct
        .get(format!("{endpoint}/v1/info"))
        .version(reqwest::Version::HTTP_10)
        .header(reqwest::header::AUTHORIZATION, &auth)
        .send()
        .await
        .expect("unsupported HTTP version response");
    assert_eq!(old_http_version.status(), reqwest::StatusCode::BAD_REQUEST);

    for (body, expected_status, expected_code) in [
        (
            r#"{"api_version":"9.0","required_features":[]}"#,
            reqwest::StatusCode::CONFLICT,
            ErrorCode::IncompatibleContract,
        ),
        (
            r#"{"api_version":"1.0","required_features":["future.required"]}"#,
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RequiredFeatureUnsupported,
        ),
    ] {
        let response = direct
            .post(format!("{endpoint}/v1/auth/revoke"))
            .header(reqwest::header::AUTHORIZATION, &auth)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .expect("incompatible request response");
        assert_eq!(response.status(), expected_status);
        let bytes = response.bytes().await.expect("safe compatibility error");
        let error: ApiError = decode_json(&bytes).expect("typed compatibility error");
        assert_eq!(error.error.code, expected_code);
    }
    assert!(
        store
            .authenticate(client_id, TokenDigest::new(digest_bytes))
            .is_ok(),
        "rejected operations must not revoke the credential"
    );
    assert_eq!(ca_pin_length, 32);
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("server task join")
        .expect("server stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_distinguishes_shutdown_version_and_required_feature_rejections() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID.to_owned()).expect("client id");
    let secret = [42_u8; 32];
    let digest = Sha256::digest(secret);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse(ENROLLMENT_ID.to_owned()).expect("enrollment id"),
            client_id,
            TokenDigest::new(digest_bytes),
        ))
        .expect("durable credential");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.base_url();
    let (ca_der, _) = server.trust_anchor();
    let direct = reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([reqwest::Certificate::from_der(ca_der).expect("CA certificate")])
        .no_proxy()
        .build()
        .expect("test HTTPS client");
    let auth = format!("Bearer {CLIENT_ID}.{}", "2a".repeat(32));
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));

    for (version, features, status, code) in [
        (
            "9.0",
            "[]",
            reqwest::StatusCode::CONFLICT,
            ErrorCode::IncompatibleContract,
        ),
        (
            "1.0",
            "[\"future.required\"]",
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RequiredFeatureUnsupported,
        ),
    ] {
        let body = format!(
            "{{\"api_version\":\"{version}\",\"kind\":\"engine.shutdown\",\"target\":{{\"kind\":\"engine\",\"instance_id\":\"{}\"}},\"options\":{{}},\"required_features\":{features}}}",
            identity.instance_id.as_str()
        );
        let response = direct
            .post(format!("{endpoint}/v1/operations"))
            .header(reqwest::header::AUTHORIZATION, &auth)
            .header("Idempotency-Key", "key_http-contract")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .expect("shutdown compatibility response");
        assert_eq!(response.status(), status);
        let body = response.bytes().await.expect("safe error body");
        let error: ApiError = decode_json(&body).expect("typed error");
        assert_eq!(error.error.code, code);
    }
    let valid_body = format!(
        "{{\"api_version\":\"1.0\",\"kind\":\"engine.shutdown\",\"target\":{{\"kind\":\"engine\",\"instance_id\":\"{}\"}},\"options\":{{}},\"required_features\":[]}}",
        identity.instance_id.as_str()
    );
    let missing_key = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(valid_body.clone())
        .send()
        .await
        .expect("missing idempotency key response");
    assert_eq!(missing_key.status(), reqwest::StatusCode::BAD_REQUEST);

    let duplicate_key = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, &auth)
        .header("Idempotency-Key", "key_http-contract")
        .header("Idempotency-Key", "key_http-contract")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(valid_body)
        .send()
        .await
        .expect("duplicate idempotency key response");
    assert_eq!(duplicate_key.status(), reqwest::StatusCode::BAD_REQUEST);

    let database = rusqlite::Connection::open(root_path.join("metadata.sqlite3"))
        .expect("read test-owned metadata");
    let operations: i64 = database
        .query_row(
            "SELECT count(*) FROM core_operations WHERE kind='engine.shutdown'",
            [],
            |row| row.get(0),
        )
        .expect("read shutdown operations");
    assert_eq!(
        operations, 0,
        "rejected requests must have no durable effect"
    );
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("server task join")
        .expect("server stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_receipt_replays_after_discard_and_concurrent_same_key_requests_converge() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID).expect("client identity");
    let secret = [42_u8; 32];
    let digest = TokenDigest::new(Sha256::digest(secret).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse(ENROLLMENT_ID).expect("enrollment identity"),
            client_id.clone(),
            digest,
        ))
        .expect("durable credential");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.base_url();
    let (ca_der, ca_pin) = server.trust_anchor();
    let ca_der = ca_der.to_vec();
    let ca_pin = *ca_pin;
    let second_client_id =
        ClientId::parse("cli_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("second client id");
    let second_secret = [55_u8; 32];
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse("enr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .expect("second enrollment id"),
            second_client_id.clone(),
            TokenDigest::new(Sha256::digest(second_secret).into()),
        ))
        .expect("second durable credential");
    let direct = reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([reqwest::Certificate::from_der(&ca_der).expect("CA certificate")])
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("test HTTPS client");
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));
    let authorization = format!("Bearer {CLIENT_ID}.{}", "2a".repeat(32));
    let key = IdempotencyKey::parse("shutdown-test-key-01").expect("idempotency key");
    let request = ShutdownRequest {
        api_version: "1.0".to_owned(),
        kind: "engine.shutdown".to_owned(),
        target: OperationTarget {
            kind: "engine".to_owned(),
            instance_id: identity.instance_id.clone(),
        },
        options: ShutdownOptions::default(),
        required_features: Vec::new(),
    };

    // Deliberately drop the first response after the engine has committed the
    // operation. No receipt is read by this caller.
    let discarded = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .header("Idempotency-Key", key.as_str())
        .json(&request)
        .send()
        .await
        .expect("accepted shutdown response");
    assert_eq!(discarded.status(), reqwest::StatusCode::CREATED);
    drop(discarded);

    let reordered = format!(
        r#"{{"required_features":[],"options":{{}},"target":{{"instance_id":"{}","kind":"engine"}},"kind":"engine.shutdown","api_version":"1.0"}}"#,
        identity.instance_id.as_str()
    );
    let reordered_replay = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .header("Idempotency-Key", key.as_str())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(reordered)
        .send()
        .await
        .expect("reordered exact replay");
    assert_eq!(reordered_replay.status(), reqwest::StatusCode::OK);
    let reordered_replay: OperationReceipt = reordered_replay
        .json()
        .await
        .expect("typed reordered replay receipt");
    assert!(reordered_replay.replayed);

    // Concurrent retries under that key must recover the same durable
    // operation instead of creating duplicate stop requests.
    let send = |request: ShutdownRequest| {
        let direct = direct.clone();
        let authorization = authorization.clone();
        let endpoint = endpoint.clone();
        let key = key.clone();
        async move {
            direct
                .post(format!("{endpoint}/v1/operations"))
                .header(reqwest::header::AUTHORIZATION, authorization)
                .header("Idempotency-Key", key.as_str())
                .json(&request)
                .send()
                .await
                .expect("concurrent shutdown request")
                .json::<OperationReceipt>()
                .await
                .expect("concurrent shutdown receipt")
        }
    };
    let (left, right) = tokio::join!(send(request.clone()), send(request.clone()));
    assert_eq!(left.operation_id, right.operation_id);
    assert!(left.replayed && right.replayed);

    // A later replay still returns the same operation after concurrent retries.
    let replay = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, &authorization)
        .header("Idempotency-Key", key.as_str())
        .json(&request)
        .send()
        .await
        .expect("same-key replay");
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    let replay: OperationReceipt = replay.json().await.expect("replayed receipt");
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, left.operation_id);
    let api_client = Client::new(
        ConnectionMaterial::new(
            endpoint.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            client_id.clone(),
            ca_der.clone(),
            ca_pin,
            SecretToken::new(secret.to_vec()).expect("secret"),
        ),
        Default::default(),
    )
    .expect("API client for own-operation read");
    let snapshot: OperationSnapshot = api_client
        .operation(left.operation_id.clone())
        .await
        .expect("own operation read");
    assert_eq!(snapshot.operation_id, left.operation_id);
    assert_eq!(snapshot.kind, "engine.shutdown");
    assert_eq!(snapshot.target.kind, "engine");
    assert_eq!(snapshot.target.instance_id, identity.instance_id);
    assert_eq!(snapshot.state, dissect3d_api::OperationState::Running);
    assert_eq!(snapshot.phase, "running");

    let not_owner = direct
        .get(format!(
            "{endpoint}/v1/operations/{}",
            left.operation_id.as_str()
        ))
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}.{}", second_client_id.as_str(), "37".repeat(32)),
        )
        .send()
        .await
        .expect("creator-only operation lookup");
    assert_eq!(not_owner.status(), reqwest::StatusCode::NOT_FOUND);
    let safe_error = not_owner.bytes().await.expect("safe not-found response");
    let safe_error: ApiError = decode_json(&safe_error).expect("strict not-found response");
    assert_eq!(safe_error.error.code, ErrorCode::NotFound);

    let wrong_instance = ShutdownRequest {
        target: OperationTarget {
            kind: "engine".to_owned(),
            instance_id: dissect3d_api::InstanceId::parse(
                "eng_ffffffffffffffffffffffffffffffff".to_owned(),
            )
            .expect("other instance"),
        },
        ..request
    };
    let conflict = direct
        .post(format!("{endpoint}/v1/operations"))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header("Idempotency-Key", key.as_str())
        .json(&wrong_instance)
        .send()
        .await
        .expect("target-instance conflict");
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("server task")
        .expect("server stopped");
    drop(store);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_client_does_not_forward_bearer_to_a_redirect_target() {
    let (ca_der, acceptor) = test_tls_acceptor();
    let redirector = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test HTTPS redirector");
    let redirect_address = redirector.local_addr().expect("redirector address");
    let trap = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test-owned redirect target trap");
    let redirect_url = format!(
        "https://127.0.0.1:{}/steal",
        trap.local_addr().expect("trap address").port()
    );
    let accept = tokio::spawn(async move {
        let (stream, _) = redirector.accept().await.expect("redirect request");
        let mut stream = acceptor.accept(stream).await.expect("redirect TLS");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buffer))
                    .await
                    .expect("redirect request deadline")
                    .expect("read redirect request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(
                request.len() <= 16_384,
                "test request exceeded header limit"
            );
        }
        stream
            .write_all(
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: {redirect_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("redirect response");
        request
    });

    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}", redirect_address.port()),
            dissect3d_api::InstallationId::parse("ins_0123456789abcdef0123456789abcdef".to_owned())
                .expect("installation id"),
            dissect3d_api::InstanceId::parse("eng_0123456789abcdef0123456789abcdef".to_owned())
                .expect("instance id"),
            ClientId::parse(CLIENT_ID.to_owned()).expect("client id"),
            ca_der.clone(),
            Sha256::digest(&ca_der).into(),
            SecretToken::new(vec![42; 32]).expect("secret"),
        ),
        Default::default(),
    )
    .expect("pinned API client");
    assert_eq!(client.info().await, Err(ClientError::InvalidResponse));
    let request = accept.await.expect("redirector task");
    assert!(
        String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("authorization: bearer ")
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), trap.accept())
            .await
            .is_err(),
        "the client followed a redirect to the credential trap"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebound_port_with_wrong_server_receives_no_bearer() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("real engine HTTPS listener");
    let address = server.endpoint();
    let (ca_der, ca_pin) = server.trust_anchor();
    let trusted_ca = ca_der.to_vec();
    let trusted_pin = *ca_pin;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(server.run(stop_rx));
    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}", address.port()),
            identity.installation_id,
            identity.instance_id,
            ClientId::parse(CLIENT_ID.to_owned()).expect("client id"),
            trusted_ca,
            trusted_pin,
            SecretToken::new(vec![42; 32]).expect("secret"),
        ),
        Default::default(),
    )
    .expect("client pinned to protected discovery CA");
    let _ = stop_tx.send(());
    server_task
        .await
        .expect("real server task join")
        .expect("real server stopped");

    let rebound = TcpListener::bind(address)
        .await
        .expect("rebind the former engine port");
    let (_, wrong_server) = test_tls_acceptor();
    let rogue = tokio::spawn(async move {
        let (stream, _) = rebound.accept().await.expect("rebound connection");
        let Ok(mut stream) = wrong_server.accept(stream).await else {
            return Vec::new();
        };
        let mut request = vec![0; 16_384];
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read(&mut request),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
        request.truncate(read);
        request
    });
    assert_eq!(client.info().await, Err(ClientError::Transport));
    let request = rogue.await.expect("rebound server task");
    assert!(
        !String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("authorization: bearer ")
    );
    drop(store);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_slow_headers_and_bodies_end_at_their_finite_deadlines() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Arc::new(Store::open(root, lease, &CorePolicy::default()).expect("store"));
    let identity = store.identity().expect("store identity");
    let client_id = ClientId::parse(CLIENT_ID.to_owned()).expect("client id");
    let secret = [42_u8; 32];
    let digest = Sha256::digest(secret);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse(ENROLLMENT_ID.to_owned()).expect("enrollment id"),
            client_id.clone(),
            TokenDigest::new(digest_bytes),
        ))
        .expect("durable credential");
    let tls_root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("TLS root");
    let server = HttpServer::bind(&tls_root, store.clone(), CorePolicy::default())
        .await
        .expect("TLS HTTP listener");
    let endpoint = server.endpoint();
    let (ca_der, ca_pin) = server.trust_anchor();
    let ca_der = ca_der.to_vec();
    let ca_pin = *ca_pin;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.clone()))
        .expect("trusted engine CA");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let (stop_tx, stop_rx) = oneshot::channel::<std::time::Instant>();
    let server_task = tokio::spawn(server.run_with_ready(stop_rx, None));

    let stream = tokio::net::TcpStream::connect(endpoint)
        .await
        .expect("slow-header connection");
    let mut stream = connector
        .connect(
            ServerName::try_from("127.0.0.1".to_owned()).expect("loopback server name"),
            stream,
        )
        .await
        .expect("trusted header-test TLS");
    let slow_header = format!(
        "GET /v1/info HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {CLIENT_ID}.{}\r\nX-Pending: ",
        endpoint.port(),
        "2a".repeat(32)
    );
    stream
        .write_all(slow_header.as_bytes())
        .await
        .expect("partial header");
    let mut response = [0_u8; 256];
    let header_result = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        stream.read(&mut response),
    )
    .await;
    assert!(
        header_result.is_ok(),
        "slow header exceeded the finite deadline"
    );

    // Time spent in headers consumes the same total request budget as the
    // later body read; each stage must not receive a fresh five seconds.
    let stream = tokio::net::TcpStream::connect(endpoint)
        .await
        .expect("cross-phase deadline connection");
    let mut stream = connector
        .connect(
            ServerName::try_from("127.0.0.1".to_owned()).expect("loopback server name"),
            stream,
        )
        .await
        .expect("trusted cross-phase TLS");
    let partial = format!(
        "POST /v1/auth/revoke HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {CLIENT_ID}.{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nX-Pending: ",
        endpoint.port(),
        "2a".repeat(32)
    );
    stream
        .write_all(partial.as_bytes())
        .await
        .expect("partial headers");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    stream
        .write_all(b"done\r\n\r\n{")
        .await
        .expect("complete headers and partial body");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.read(&mut response),
    )
    .await
    .expect("total request deadline closes the staged request");
    assert!(
        matches!(read_result, Ok(0))
            || matches!(read_result, Err(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof),
        "expired TLS request must close without a response: {read_result:?}"
    );
    assert!(
        store
            .authenticate(client_id.clone(), TokenDigest::new(digest_bytes))
            .is_ok(),
        "an expired multi-stage request must not commit revocation"
    );

    let stream = tokio::net::TcpStream::connect(endpoint)
        .await
        .expect("slow-body connection");
    let mut stream = connector
        .connect(
            ServerName::try_from("127.0.0.1".to_owned()).expect("loopback server name"),
            stream,
        )
        .await
        .expect("trusted body-test TLS");
    let slow_body_header = format!(
        "POST /v1/auth/revoke HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {CLIENT_ID}.{}\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{\"",
        endpoint.port(),
        "2a".repeat(32)
    );
    stream
        .write_all(slow_body_header.as_bytes())
        .await
        .expect("partial JSON body");
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        stream.read(&mut response),
    )
    .await
    .expect("slow body response deadline")
    .expect("slow body response");
    let response = String::from_utf8_lossy(&response[..received]);
    assert!(response.starts_with("HTTP/1.1 408"), "response: {response}");
    assert!(
        store
            .authenticate(client_id, TokenDigest::new(digest_bytes))
            .is_ok(),
        "an incomplete slow body must not commit revocation"
    );
    // Keep a second authenticated mutation stalled while an accepted shutdown
    // starts its one observation budget. The server must close that request
    // when the same absolute deadline reaches the HTTP drain stage.
    let stalled = tokio::net::TcpStream::connect(endpoint)
        .await
        .expect("shutdown slow-body connection");
    let mut stalled = connector
        .connect(
            ServerName::try_from("127.0.0.1".to_owned()).expect("loopback server name"),
            stalled,
        )
        .await
        .expect("trusted shutdown slow-body TLS");
    let partial = format!(
        "POST /v1/auth/revoke HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {CLIENT_ID}.{}\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{\"",
        endpoint.port(),
        "2a".repeat(32)
    );
    stalled
        .write_all(partial.as_bytes())
        .await
        .expect("partial body");
    let current = store.identity().expect("current service identity");
    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}", endpoint.port()),
            current.installation_id,
            current.instance_id,
            ClientId::parse(CLIENT_ID.to_owned()).expect("client id"),
            ca_der,
            ca_pin,
            SecretToken::new(vec![42; 32]).expect("secret"),
        ),
        Default::default(),
    )
    .expect("authenticated test client");
    let key = IdempotencyKey::parse("slow-body-shutdown-1").expect("shutdown key");
    let receipt = client
        .shutdown(key)
        .await
        .expect("durable shutdown receipt");
    assert_eq!(receipt.state, dissect3d_api::OperationState::Queued);
    assert_eq!(
        client.info().await.expect("stopping engine info").phase,
        dissect3d_api::EnginePhase::Stopping
    );
    assert_eq!(
        client
            .operation(receipt.operation_id.clone())
            .await
            .expect("shutdown operation state")
            .phase,
        "running"
    );
    let started = tokio::time::Instant::now();
    let _ = stop_tx.send(std::time::Instant::now() + std::time::Duration::from_millis(200));
    server_task
        .await
        .expect("server task join")
        .expect("server stopped");
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    drop(stalled);
}

fn test_tls_acceptor() -> (Vec<u8>, TlsAcceptor) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().expect("test CA key");
    let mut ca_parameters = CertificateParams::default();
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_certificate = ca_parameters
        .self_signed(&ca_key)
        .expect("test CA certificate");
    let issuer = Issuer::from_ca_cert_der(ca_certificate.der(), ca_key).expect("test issuer");

    let leaf_key = KeyPair::generate().expect("test TLS key");
    let mut leaf_parameters =
        CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("loopback SAN");
    leaf_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_parameters
        .signed_by(&leaf_key, &issuer)
        .expect("test TLS certificate");
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], private_key)
        .expect("test TLS configuration");
    (
        ca_certificate.der().to_vec(),
        TlsAcceptor::from(Arc::new(config)),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_enforces_response_compatibility_and_normalizes_root_urls() {
    let installation = "ins_0123456789abcdef0123456789abcdef";
    let instance = "eng_0123456789abcdef0123456789abcdef";
    let ordinary = serde_json::json!({
        "api_version":"1.0", "engine_version":"test", "installation_id":installation,
        "instance_id":instance, "phase":"ready", "supported_operations":["engine.info"],
        "granted_operations":["engine.info"], "required_features":[], "limits":{},
        "platform":{"os":"test","architecture":"test"}
    });
    for case in ["required_feature", "error_version", "trailing_slash"] {
        let mut body = ordinary.clone();
        let status = if case == "error_version" {
            body = serde_json::json!({"api_version":"99.0", "error":{
                "code":"unauthorized", "message":"safe", "correlation_id":"corr_0123456789abcdef0123456789abcdef", "retryable":false
            }});
            "401 Unauthorized"
        } else {
            "200 OK"
        };
        if case == "required_feature" {
            body["required_features"] = serde_json::json!(["unknown.future.feature"]);
        }
        let body = serde_json::to_vec(&body).unwrap();
        let (ca, acceptor) = test_tls_acceptor();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut request = Vec::new();
            let mut bytes = [0; 1024];
            while !request.windows(4).any(|chunk| chunk == b"\r\n\r\n") {
                let count = socket.read(&mut bytes).await.unwrap();
                assert!(count > 0);
                request.extend_from_slice(&bytes[..count]);
            }
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            request
        });
        let client = Client::new(
            ConnectionMaterial::new(
                format!(
                    "https://127.0.0.1:{port}{}",
                    if case == "trailing_slash" { "/" } else { "" }
                ),
                dissect3d_api::InstallationId::parse(installation).unwrap(),
                dissect3d_api::InstanceId::parse(instance).unwrap(),
                ClientId::parse(CLIENT_ID).unwrap(),
                ca.clone(),
                Sha256::digest(&ca).into(),
                SecretToken::new(vec![42; 32]).unwrap(),
            ),
            Default::default(),
        )
        .unwrap();
        let result = client.info().await;
        let request = server.await.unwrap();
        if case == "trailing_slash" {
            assert!(request.starts_with(b"GET /v1/info HTTP/1.1\r\n"));
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(ClientError::Incompatible), "{case}");
        }
    }
}
