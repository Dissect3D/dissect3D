//! Scripted TLS peer tests the real API client transport, not engine activation.
#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test helpers; engineering.md Rule 6 permits unwrap in test setup"
)]
use dissect3d_api::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
};

fn test_tls_acceptor() -> (Vec<u8>, TlsAcceptor) {
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
        CertificateParams::new(vec![Ipv4Addr::LOCALHOST.to_string()]).expect("loopback SAN");
    leaf_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_parameters
        .signed_by(&leaf_key, &issuer)
        .expect("signed test TLS certificate");
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], private_key)
        .expect("TLS server config");
    (
        ca_certificate.der().to_vec(),
        TlsAcceptor::from(Arc::new(config)),
    )
}

struct Exchange {
    path: &'static str,
    negotiated: bool,
    body: Vec<u8>,
    response: Option<Vec<u8>>,
    status: u16,
}

async fn peer(exchanges: Vec<Exchange>) -> (Client, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (ca, acceptor) = test_tls_acceptor();
    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}/", address.port()),
            InstallationId::parse("ins_0123456789abcdef0123456789abcdef").unwrap(),
            InstanceId::parse("eng_0123456789abcdef0123456789abcdef").unwrap(),
            ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
            ca.clone(),
            Sha256::digest(ca).into(),
            SecretToken::new(vec![0x5a; 32]).unwrap(),
        ),
        ClientLimits::default(),
    )
    .unwrap();
    let task = tokio::spawn(async move {
        for exchange in exchanges {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            let end = loop {
                let n = stream.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&buffer[..n]);
                assert!(bytes.len() <= 100_000);
                if let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8(bytes[..end].to_vec())
                .unwrap()
                .to_ascii_lowercase();
            assert!(headers.starts_with(exchange.path));
            assert_eq!(
                headers.contains("dissect3d-job-contract: we-0.1\r\n"),
                exchange.negotiated
            );
            if !exchange.body.is_empty() {
                assert!(headers.contains("content-type: application/json\r\n"));
                assert!(headers.contains("idempotency-key: same-key\r\n"));
                assert!(headers.contains(&format!("content-length: {}\r\n", exchange.body.len())));
            }
            while bytes.len() - end < exchange.body.len() {
                let n = stream.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                bytes.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(&bytes[end..], exchange.body);
            if let Some(body) = exchange.response {
                stream.write_all(format!("HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",exchange.status,body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
        }
    });
    (client, task)
}

fn info() -> Exchange {
    Exchange {
        path: "get /v1/info ",
        negotiated: false,
        body: vec![],
        response: Some(include_bytes!("../../api/tests/fixtures/execution-info.json").to_vec()),
        status: 200,
    }
}
fn legacy() -> Vec<u8> {
    br#"{ "api_version":"1.0","support_ref":"old","task":{"id":"copy","version":"1.0"},"inputs":{"mesh":[{"input_id":"inp_11111111111111111111111111111111"}]},"parameters":{"n":1e0},"required_features":[],"evaluation_consent":false }
"#.to_vec()
}

#[tokio::test]
async fn lost_reply_then_exact_legacy_replay_uses_same_key_header_and_body() {
    let body = ExecutionSubmissionBody::replay(legacy()).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../api/tests/fixtures/execution-snapshot.json"
    ))
    .unwrap();
    let receipt = serde_json::json!({"api_version":"1.0","job_contract":"we-0.1","accepted":true,"job_id":"job_22222222222222222222222222222222","replayed":true,"acceptance_sequence":1,"snapshot_revision":1,"resolved":snapshot["resolved"],"retry_of":null});
    let post = |response| Exchange {
        path: "post /v1/jobs ",
        negotiated: true,
        body: legacy(),
        response,
        status: 200,
    };
    let (client, task) = peer(vec![
        info(),
        post(None),
        info(),
        post(Some(serde_json::to_vec(&receipt).unwrap())),
    ])
    .await;
    let key = IdempotencyKey::parse("same-key").unwrap();
    assert!(matches!(
        client.submit_execution_job(&key, &body).await,
        Err(SubmissionClientError::Uncertain { .. })
    ));
    let replay = client.submit_execution_job(&key, &body).await.unwrap();
    assert_eq!(
        replay.job_id.as_str(),
        "job_22222222222222222222222222222222"
    );
    assert!(replay.replayed);
    task.await.unwrap();
}

#[tokio::test]
async fn mixed_legacy_reads_refuse_while_core_info_and_execution_reads_work() {
    let snapshot = include_bytes!("../../api/tests/fixtures/execution-snapshot.json").to_vec();
    let (client, task) = peer(vec![
        info(),
        info(),
        info(),
        info(),
        Exchange {
            path: "get /v1/jobs/job_22222222222222222222222222222222 ",
            negotiated: true,
            body: vec![],
            response: Some(snapshot),
            status: 200,
        },
    ])
    .await;
    assert!(client.info().await.is_ok());
    assert_eq!(
        client.jobs(JobsQuery::default()).await,
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );
    let id = JobId::parse("job_22222222222222222222222222222222").unwrap();
    assert_eq!(
        client.job(&id).await,
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );
    assert_eq!(
        client.execution_job(&id).await.unwrap().summary.state,
        ExecutionJobState::Succeeded
    );
    task.await.unwrap();
}

#[tokio::test]
async fn submission_rejects_a_retry_receipt_and_retry_retains_definitive_rejection() {
    let snapshot: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../api/tests/fixtures/execution-snapshot.json"
    ))
    .unwrap();
    let receipt = serde_json::json!({"api_version":"1.0","job_contract":"we-0.1","accepted":true,"job_id":"job_22222222222222222222222222222222","replayed":true,"acceptance_sequence":1,"snapshot_revision":1,"resolved":snapshot["resolved"],"retry_of":"job_33333333333333333333333333333333"});
    let error=br#"{"api_version":"1.0","error":{"code":"job_not_terminal","message":"safe","correlation_id":"corr_11111111111111111111111111111111","retryable":false}}"#.to_vec();
    let (client, task) = peer(vec![
        info(),
        Exchange {
            path: "post /v1/jobs ",
            negotiated: true,
            body: legacy(),
            response: Some(serde_json::to_vec(&receipt).unwrap()),
            status: 200,
        },
        info(),
        Exchange {
            path: "post /v1/jobs/job_33333333333333333333333333333333/retry ",
            negotiated: true,
            body: br#"{"api_version":"1.0","required_features":[]}"#.to_vec(),
            response: Some(error),
            status: 409,
        },
    ])
    .await;
    let key = IdempotencyKey::parse("same-key").unwrap();
    let wrong = client
        .submit_execution_job(&key, &ExecutionSubmissionBody::replay(legacy()).unwrap())
        .await;
    assert!(
        matches!(wrong, Err(SubmissionClientError::Uncertain { .. })),
        "retry receipt cannot acknowledge a submission"
    );
    let source = JobId::parse("job_33333333333333333333333333333333").unwrap();
    let rejection = client.retry_execution_job(&source, &key).await;
    assert!(
        matches!(rejection,Err(SubmissionClientError::Rejected(ref error)) if error.error.code==ErrorCode::JobNotTerminal)
    );
    task.await.unwrap();
}
