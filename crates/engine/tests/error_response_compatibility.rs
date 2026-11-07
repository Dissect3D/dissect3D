use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dissect3d_api::{
    Client, ClientError, ClientId, ClientLimits, ConnectionMaterial, ErrorCode, InstallationId,
    InstanceId, SecretToken,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

fn server_config() -> (Vec<u8>, Arc<ServerConfig>) {
    let ca_key = KeyPair::generate().expect("generate test CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).expect("create test CA");
    let ca_der = ca.der().to_vec();
    let ca_certificate = CertificateDer::from(ca_der.clone());
    let issuer = Issuer::from_ca_cert_der(&ca_certificate, ca_key).expect("load test issuer");

    let leaf_key = KeyPair::generate().expect("generate test leaf key");
    let mut leaf_params = CertificateParams::new(vec![Ipv4Addr::LOCALHOST.to_string()])
        .expect("create loopback leaf parameters");
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "API compatibility test server");
    leaf_params.distinguished_name = distinguished_name;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("sign test leaf");
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], private_key)
        .expect("configure test TLS peer");
    (ca_der, Arc::new(config))
}

async fn request_error(body: &'static str) -> Result<(), ClientError> {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind test server");
    let address = listener.local_addr().expect("read test server address");
    let (ca_der, config) = server_config();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept API client");
        let acceptor = TlsAcceptor::from(config);
        let mut stream = acceptor.accept(stream).await.expect("TLS handshake");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await.expect("read HTTP request");
            assert_ne!(count, 0, "client closed before sending request headers");
            request.extend_from_slice(&buffer[..count]);
        }
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("write error response");
    });

    let material = ConnectionMaterial::new(
        format!("https://127.0.0.1:{}/", address.port()),
        InstallationId::parse("ins_0123456789abcdef0123456789abcdef").unwrap(),
        InstanceId::parse("eng_0123456789abcdef0123456789abcdef").unwrap(),
        ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
        ca_der.clone(),
        Sha256::digest(ca_der).into(),
        SecretToken::new(vec![0x5a; 32]).unwrap(),
    );
    let client = match Client::new(material, ClientLimits::default()) {
        Ok(client) => client,
        Err(error) => {
            server.abort();
            return Err(error);
        }
    };
    let result = client.info().await.map(|_| ());
    if result.is_err() && !server.is_finished() {
        server.abort();
    }
    server.await.expect("test server task");
    result
}

#[tokio::test]
async fn real_client_preserves_error_compatibility_and_version_checks() {
    let compatible = r#"{"api_version":"1.0","error":{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false,"optional_hint":{"documentation":"access"}},"optional_envelope_hint":{"retry":false}}"#;
    let error = request_error(compatible)
        .await
        .expect_err("compatible remote error must retain its category");
    assert_eq!(error, ClientError::Rejected(ErrorCode::Unauthorized));
    assert_eq!(error.to_string(), "engine rejected the request");

    let incompatible_version = r#"{"api_version":"2.0","error":{"code":"unauthorized","message":"Access denied","correlation_id":"corr_0123456789abcdef0123456789abcdef","retryable":false,"optional_hint":true}}"#;
    assert_eq!(
        request_error(incompatible_version).await,
        Err(ClientError::Incompatible)
    );
}
