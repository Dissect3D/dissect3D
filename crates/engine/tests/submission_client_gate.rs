use dissect3d_api::{
    Client, ClientError, ClientId, ClientLimits, ConnectionMaterial, ErrorCode, InstallationId,
    InstanceId, SecretToken,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

const INSTALLATION_ID: &str = "ins_0123456789abcdef0123456789abcdef";
const INSTANCE_ID: &str = "eng_0123456789abcdef0123456789abcdef";
const CLIENT_ID: &str = "cli_0123456789abcdef0123456789abcdef";

struct CountingReader(Arc<AtomicUsize>);

impl AsyncRead for CountingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().0.fetch_add(1, Ordering::SeqCst);
        if buffer.remaining() > 0 {
            buffer.put_slice(&[7]);
        }
        Poll::Ready(Ok(()))
    }
}

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

async fn create_input_result(
    submission: Option<serde_json::Value>,
    grants: Vec<&'static str>,
) -> (Result<dissect3d_api::InputReceipt, ClientError>, usize) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind test HTTPS server");
    let address = listener.local_addr().expect("test server address");
    let (ca_der, acceptor) = test_tls_acceptor();
    let mut body = serde_json::json!({
        "api_version": "1.0",
        "engine_version": "test",
        "installation_id": INSTALLATION_ID,
        "instance_id": INSTANCE_ID,
        "phase": "ready",
        "supported_operations": ["engine.info"],
        "granted_operations": grants,
        "required_features": [],
        "limits": {},
        "platform": {"os": "test", "architecture": "test"}
    });
    if let Some(submission) = submission {
        body["submission"] = submission;
    }
    let body = serde_json::to_vec(&body).expect("encode info response");
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept client");
        let mut stream = acceptor.accept(stream).await.expect("TLS handshake");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream
                .read(&mut buffer)
                .await
                .expect("read request headers");
            assert_ne!(count, 0, "client ended before request headers");
            request.extend_from_slice(&buffer[..count]);
            assert!(request.len() <= 16_384, "bounded request headers");
        }
        assert!(request.starts_with(b"GET /v1/info HTTP/1.1\r\n"));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write response headers");
        stream.write_all(&body).await.expect("write response body");
    });
    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}/", address.port()),
            InstallationId::parse(INSTALLATION_ID.to_owned()).expect("installation ID"),
            InstanceId::parse(INSTANCE_ID.to_owned()).expect("instance ID"),
            ClientId::parse(CLIENT_ID.to_owned()).expect("client ID"),
            ca_der.clone(),
            Sha256::digest(ca_der).into(),
            SecretToken::new(vec![0x5a; 32]).expect("secret"),
        ),
        ClientLimits::default(),
    )
    .expect("trusted API client");
    let read_count = Arc::new(AtomicUsize::new(0));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.create_input(
            CountingReader(read_count.clone()),
            1,
            "application/octet-stream",
        ),
    )
    .await
    .expect("capability check must finish before upload");
    server_task.await.expect("test server task");
    (result, read_count.load(Ordering::SeqCst))
}

#[tokio::test]
async fn inactive_or_incompatible_capability_rejects_before_reading_the_input() {
    let (without_capability, missing_capability_reads) =
        create_input_result(None, vec!["engine.info"]).await;
    assert_eq!(
        without_capability,
        Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
    );
    assert_eq!(missing_capability_reads, 0);

    let incompatible = serde_json::json!({
        "version": "2.0",
        "dispatch_enabled": false,
        "operations": ["inputs.create", "jobs.submit", "jobs.list", "jobs.show"],
        "limits": {},
        "limits_source": "test"
    });
    let (wrong_version, wrong_version_reads) =
        create_input_result(Some(incompatible), vec!["engine.info", "inputs.create"]).await;
    assert_eq!(
        wrong_version,
        Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
    );
    assert_eq!(wrong_version_reads, 0);
}
