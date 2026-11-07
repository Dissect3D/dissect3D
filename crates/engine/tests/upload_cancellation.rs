use dissect3d_api::{
    Client, ClientId, ClientLimits, ConnectionMaterial, InstallationId, InstanceId, SecretToken,
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

struct WaitingReader {
    polled: Arc<tokio::sync::Notify>,
    dropped: Arc<tokio::sync::Notify>,
}
impl Drop for WaitingReader {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}
impl AsyncRead for WaitingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polled.notify_one();
        Poll::Pending
    }
}

#[tokio::test]
async fn cancelling_complete_upload_releases_a_waiting_source() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (ca, acceptor) = test_tls_acceptor();
    let limits: std::collections::BTreeMap<&str, u64> = LIMITS.iter().copied().collect();
    let info = serde_json::to_vec(&serde_json::json!({
        "api_version":"1.0", "engine_version":"test",
        "installation_id":INSTALLATION_ID, "instance_id":INSTANCE_ID,
        "phase":"ready", "supported_operations":["engine.info"],
        "granted_operations":["engine.info","inputs.create"], "required_features":[],
        "limits":{}, "platform":{"os":"test","architecture":"test"},
        "submission":{"version":"1.0", "dispatch_enabled":false,
            "operations":["inputs.create","jobs.submit","jobs.list","jobs.show"],
            "limits":limits, "limits_source":"built_in"}
    }))
    .unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
            assert!(headers.len() <= 16_384);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            info.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.write_all(&info).await.unwrap();
        drop(stream);
        // Retain the listener and upload connection until the owner cancels.
        let (socket, _) = listener.accept().await.unwrap();
        let _stream = acceptor.accept(socket).await;
        std::future::pending::<()>().await;
    });
    let client = Client::new(
        ConnectionMaterial::new(
            format!("https://127.0.0.1:{}/", address.port()),
            InstallationId::parse(INSTALLATION_ID).unwrap(),
            InstanceId::parse(INSTANCE_ID).unwrap(),
            ClientId::parse(CLIENT_ID).unwrap(),
            ca.clone(),
            Sha256::digest(&ca).into(),
            SecretToken::new(vec![0x5a; 32]).unwrap(),
        ),
        ClientLimits::default(),
    )
    .unwrap();
    let polled = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(tokio::sync::Notify::new());
    let reader = WaitingReader {
        polled: polled.clone(),
        dropped: dropped.clone(),
    };
    let upload = tokio::spawn(async move {
        client
            .create_input(reader, 1, "application/octet-stream")
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), polled.notified())
        .await
        .expect("source must be waiting inside upload");
    upload.abort();
    assert!(upload.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(1), dropped.notified())
        .await
        .expect("cancelled upload left its source reader alive");
    server.abort();
}
const LIMITS: &[(&str, u64)] = &[
    ("input_bytes_max", 268_435_456),
    ("job_input_bytes_max", 1_073_741_824),
    ("upload_concurrency_max", 2),
    ("staging_reserved_bytes_max", 2_147_483_648),
    ("staged_input_ttl_ms", 86_400_000),
    ("upload_idle_timeout_ms", 30_000),
    ("upload_total_timeout_ms", 600_000),
    ("queued_jobs_max", 128),
    ("submission_bindings_max", 65_536),
    ("submission_binding_bytes_max", 16_384),
    ("captured_input_bytes_max", 17_179_869_184),
    ("storage_free_reserve_bytes", 1_073_741_824),
    ("job_control_bytes_max", 65_536),
    ("job_metadata_bytes_max", 262_144),
    ("job_inputs_max", 64),
    ("job_roles_max", 16),
    ("job_list_default", 20),
    ("job_list_max", 100),
    ("job_cursor_bytes_max", 1_024),
];
