//! Installation-scoped certificate authority and per-instance HTTPS identity.
//!
//! The CA certificate and signing key are created once inside the protected
//! engine root. Each engine run creates a short-lived loopback leaf certificate;
//! clients receive only the CA certificate and its SHA-256 pin through native
//! protected discovery.

use dissect3d_platform::{OwnedRoot, PlatformError, RelativePath};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

const CA_CERTIFICATE: &str = "tls/installation-ca.der";
const CA_PRIVATE_KEY: &str = "tls/installation-ca-key.der";
const MAX_CERTIFICATE_BYTES: usize = 65_536;

/// Ready TLS server keys and public native-discovery trust material.
pub(crate) struct TlsMaterial {
    pub(crate) ca_der: Vec<u8>,
    pub(crate) ca_sha256: [u8; 32],
    pub(crate) server: Arc<ServerConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlsError {
    Store,
    Certificate,
}

impl From<PlatformError> for TlsError {
    fn from(_: PlatformError) -> Self {
        Self::Store
    }
}

impl TlsMaterial {
    /// Load the stable installation CA, creating it only when both files are
    /// absent. A partial or invalid pair is preserved and causes safe refusal.
    pub(crate) fn load_or_create(root: &OwnedRoot) -> Result<Self, TlsError> {
        root.ensure_private_directory(&RelativePath::parse("tls")?)?;
        let certificate_path = RelativePath::parse(CA_CERTIFICATE)?;
        let key_path = RelativePath::parse(CA_PRIVATE_KEY)?;
        let certificate_exists = root.file_metadata(&certificate_path);
        let key_exists = root.file_metadata(&key_path);
        let (ca_der, ca_key_der) = match (certificate_exists, key_exists) {
            (Err(PlatformError::NotFound), Err(PlatformError::NotFound)) => {
                let (certificate, key) = create_ca()?;
                root.write_atomic(&certificate_path, &certificate)?;
                root.write_atomic(&key_path, &key)?;
                (certificate, key)
            }
            (Ok(certificate_metadata), Ok(key_metadata))
                if certificate_metadata.length > 0
                    && certificate_metadata.length <= MAX_CERTIFICATE_BYTES as u64
                    && key_metadata.length > 0
                    && key_metadata.length <= MAX_CERTIFICATE_BYTES as u64 =>
            {
                (
                    root.read_file(&certificate_path, MAX_CERTIFICATE_BYTES)?,
                    root.read_file(&key_path, MAX_CERTIFICATE_BYTES)?,
                )
            }
            _ => return Err(TlsError::Store),
        };
        let server = create_server_config(&ca_der, &ca_key_der)?;
        let ca_sha256 = Sha256::digest(&ca_der).into();
        Ok(Self {
            ca_der,
            ca_sha256,
            server,
        })
    }
}

fn create_ca() -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key = KeyPair::generate().map_err(|_| TlsError::Certificate)?;
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let certificate = parameters
        .self_signed(&key)
        .map_err(|_| TlsError::Certificate)?;
    Ok((certificate.der().to_vec(), key.serialize_der()))
}

fn create_server_config(ca_der: &[u8], ca_key_der: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let ca_key = PrivatePkcs8KeyDer::from(ca_key_der.to_vec());
    let signing_key = KeyPair::try_from(&ca_key).map_err(|_| TlsError::Certificate)?;
    let ca_certificate = CertificateDer::from(ca_der.to_vec());
    let issuer = Issuer::from_ca_cert_der(&ca_certificate, signing_key)
        .map_err(|_| TlsError::Certificate)?;

    let leaf_key = KeyPair::generate().map_err(|_| TlsError::Certificate)?;
    let mut leaf_parameters =
        CertificateParams::new(vec![IpAddr::V4(Ipv4Addr::LOCALHOST).to_string()])
            .map_err(|_| TlsError::Certificate)?;
    // Keep the leaf subject distinct from the installation CA subject. Both
    // otherwise inherit rcgen's generic default CN, which makes OpenSSL treat
    // the presented leaf as self-signed when building a path to the pinned CA.
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "Dissect3D loopback server");
    leaf_parameters.distinguished_name = distinguished_name;
    leaf_parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_parameters
        .signed_by(&leaf_key, &issuer)
        .map_err(|_| TlsError::Certificate)?;
    // rcgen accepts an issuer key independently of its certificate. Verify
    // the chain a pinned client will see before publishing native readiness.
    use tokio_rustls::rustls::{
        RootCertStore,
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
        pki_types::{ServerName, UnixTime},
    };
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_certificate)
        .map_err(|_| TlsError::Certificate)?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|_| TlsError::Certificate)?;
    verifier
        .verify_server_cert(
            leaf.der(),
            &[],
            &ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()),
            &[],
            UnixTime::now(),
        )
        .map_err(|_| TlsError::Certificate)?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf.der().to_vec())], private_key)
        .map_err(|_| TlsError::Certificate)?;
    Ok(Arc::new(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_ca_certificate_and_key_cannot_publish_https_readiness() {
        let (certificate, key) = create_ca().unwrap();
        let (_, different_key) = create_ca().unwrap();
        assert!(create_server_config(&certificate, &key).is_ok());
        assert!(create_server_config(&certificate, &different_key).is_err());
    }
}
