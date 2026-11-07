//! Protected profile credentials and verified engine discovery.
//!
//! The CLI treats the descriptor as an untrusted hint until its file is read
//! beneath an owner-validated root, its process start marker matches, and the
//! native channel confirms the current engine instance.

use dissect3d_api::{
    BootstrapAddress, Client, ClientId, ClientLimits, ConnectionMaterial, DiscoveryRecord,
    EnrollmentId, EnrollmentReceipt, IdempotencyKey, InstallationId, InstanceId, OperationId,
    OperationReceipt, SecretToken, decode_json,
};
use dissect3d_platform::{
    BootstrapEndpoint, OwnedRoot, PlatformError, RelativePath, RootPurpose, connect_bootstrap,
    current_owner_identity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROFILE_FILE: &str = "credential.json";
const MAX_PROFILE_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionError {
    Unavailable,
    Unauthorized,
    Incompatible,
    Storage,
    Invalid,
    Capacity,
    Conflict,
    EnrollmentRejected,
    ProfileBusy,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileCredential {
    pub(crate) installation_id: InstallationId,
    pub(crate) instance_id: InstanceId,
    pub(crate) client_id: ClientId,
    pub(crate) enrollment_id: EnrollmentId,
    pub(crate) secret_hex: String,
    pub(crate) state: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) submission_access: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

pub(crate) struct AccessCredential {
    pub(crate) installation_id: InstallationId,
    pub(crate) instance_id: InstanceId,
    pub(crate) client_id: ClientId,
    pub(crate) secret_hex: String,
}

impl Drop for AccessCredential {
    fn drop(&mut self) {
        let mut secret = std::mem::take(&mut self.secret_hex).into_bytes();
        secret.fill(0);
    }
}

impl From<ProfileCredential> for AccessCredential {
    fn from(value: ProfileCredential) -> Self {
        Self {
            installation_id: value.installation_id.clone(),
            instance_id: value.instance_id.clone(),
            client_id: value.client_id.clone(),
            secret_hex: value.secret_hex.clone(),
        }
    }
}

impl Drop for ProfileCredential {
    fn drop(&mut self) {
        let mut secret = std::mem::take(&mut self.secret_hex).into_bytes();
        secret.fill(0);
    }
}

pub(crate) struct Profile {
    root: OwnedRoot,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingStop {
    pub(crate) installation_id: InstallationId,
    pub(crate) instance_id: InstanceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) connection_binding: Option<String>,
    pub(crate) pid: u32,
    pub(crate) start_marker: String,
    pub(crate) idempotency_key: IdempotencyKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) receipt: Option<OperationReceipt>,
    pub(crate) state: String,
}

pub(crate) fn connection_binding(root: &Path) -> String {
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        encoded.push(char::from(b"0123456789abcdef"[(byte & 15) as usize]));
    }
    encoded
}

impl Profile {
    pub(crate) fn open_existing(config_path: &Path) -> Result<Self, ConnectionError> {
        let mut path = config_path.as_os_str().to_os_string();
        path.push(".state");
        let root =
            OwnedRoot::open(Path::new(&path), RootPurpose::ClientConfig).map_err(|error| {
                if error == PlatformError::NotFound {
                    ConnectionError::Unavailable
                } else {
                    ConnectionError::Storage
                }
            })?;
        Ok(Self { root })
    }

    pub(crate) fn root(&self) -> &OwnedRoot {
        &self.root
    }

    pub(crate) fn open(config_path: &Path) -> Result<Self, ConnectionError> {
        let mut state_path = config_path.as_os_str().to_os_string();
        state_path.push(".state");
        let root_path = PathBuf::from(state_path);
        let root = if root_path.exists() {
            OwnedRoot::open(&root_path, RootPurpose::ClientConfig)
        } else {
            OwnedRoot::create_private(&root_path, RootPurpose::ClientConfig)
        }
        .map_err(|_| ConnectionError::Storage)?;
        root.ensure_private_directory(
            &RelativePath::parse("credentials").map_err(|_| ConnectionError::Storage)?,
        )
        .map_err(|_| ConnectionError::Storage)?;
        Ok(Self { root })
    }

    /// Serialize profile read-modify-write workflows across CLI processes.
    /// Busy is a safe rejection before enrollment/revocation/stop submission.
    pub(crate) fn lock_control(
        &self,
    ) -> Result<dissect3d_platform::AuthorityLease, ConnectionError> {
        dissect3d_platform::AuthorityLease::acquire(&self.root).map_err(|error| {
            if error == PlatformError::Busy {
                ConnectionError::ProfileBusy
            } else {
                ConnectionError::Storage
            }
        })
    }

    pub(crate) fn load(&self) -> Result<Option<ProfileCredential>, ConnectionError> {
        let path = RelativePath::parse(PROFILE_FILE).map_err(|_| ConnectionError::Storage)?;
        let mut bytes = match self.root.read_file(&path, MAX_PROFILE_BYTES) {
            Ok(bytes) => bytes,
            Err(PlatformError::NotFound) => return Ok(None),
            Err(_) => return Err(ConnectionError::Storage),
        };
        let mut credential: ProfileCredential =
            decode_json(&bytes).map_err(|_| ConnectionError::Invalid)?;
        // Stored tokens are deliberately represented as hex so the JSON
        // record can be strictly decoded; promptly clear the file buffer.
        bytes.fill(0);
        let valid_secret = credential.state == "revoked" && credential.secret_hex.is_empty()
            || credential.secret_hex.len() == 64
                && credential
                    .secret_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid_secret || !matches!(credential.state.as_str(), "pending" | "active" | "revoked") {
            credential.secret_hex.clear();
            return Err(ConnectionError::Invalid);
        }
        Ok(Some(credential))
    }

    pub(crate) fn has_saved_records(&self) -> Result<bool, ConnectionError> {
        if self.load()?.is_some() {
            return Ok(true);
        }
        Ok(self.load_pending_stop()?.is_some())
    }

    /// Reconcile an active installation credential to a freshly verified
    /// instance before constructing any authenticated client.
    pub(crate) fn active_credential(
        &self,
        engine: &DiscoveredEngine,
    ) -> Result<ProfileCredential, ConnectionError> {
        let mut credential = self.load()?.ok_or(ConnectionError::Unauthorized)?;
        if credential.state != "active"
            || credential.installation_id != engine.discovery.installation_id
        {
            return Err(ConnectionError::Unauthorized);
        }
        if credential.instance_id != engine.discovery.instance_id {
            credential.instance_id = engine.discovery.instance_id.clone();
            self.save(&credential)?;
        }
        Ok(credential)
    }

    pub(crate) fn selected_credential(
        &self,
        config: &crate::config::ConfigFile,
        engine: &DiscoveredEngine,
    ) -> Result<AccessCredential, ConnectionError> {
        let Some((file, installation)) = config
            .explicit_credential_reference()
            .map_err(|_| ConnectionError::Invalid)?
        else {
            return self.active_credential(engine).map(Into::into);
        };
        let installation_id =
            InstallationId::parse(installation).map_err(|_| ConnectionError::Invalid)?;
        if installation_id != engine.discovery.installation_id {
            return Err(ConnectionError::Incompatible);
        }
        let path = Path::new(file);
        let parent = path
            .parent()
            .filter(|parent| parent.is_absolute())
            .ok_or(ConnectionError::Invalid)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ConnectionError::Invalid)?;
        let root = OwnedRoot::open(parent, RootPurpose::ClientConfig)
            .map_err(|_| ConnectionError::Storage)?;
        let relative =
            RelativePath::parse(name.to_owned()).map_err(|_| ConnectionError::Invalid)?;
        let mut bytes = root
            .read_file(&relative, 512)
            .map_err(|_| ConnectionError::Storage)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
            bytes.fill(0);
            return Err(ConnectionError::Invalid);
        }
        let decoded = match std::str::from_utf8(&bytes) {
            Ok(decoded) => decoded,
            Err(_) => {
                bytes.fill(0);
                return Err(ConnectionError::Invalid);
            }
        };
        let (client, secret) = match decoded.split_once('.') {
            Some(parts) => parts,
            None => {
                bytes.fill(0);
                return Err(ConnectionError::Invalid);
            }
        };
        if secret.contains('.') {
            bytes.fill(0);
            return Err(ConnectionError::Invalid);
        }
        let client_id = match ClientId::parse(client.to_owned()) {
            Ok(client_id) => client_id,
            Err(_) => {
                bytes.fill(0);
                return Err(ConnectionError::Invalid);
            }
        };
        if secret.len() != 64
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bytes.fill(0);
            return Err(ConnectionError::Invalid);
        }
        let secret_hex = secret.to_owned();
        bytes.fill(0);
        Ok(AccessCredential {
            installation_id,
            instance_id: engine.discovery.instance_id.clone(),
            client_id,
            secret_hex,
        })
    }

    pub(crate) fn save(&self, credential: &ProfileCredential) -> Result<(), ConnectionError> {
        let bytes = serde_json::to_vec(credential).map_err(|_| ConnectionError::Invalid)?;
        self.root
            .write_atomic(
                &RelativePath::parse(PROFILE_FILE).map_err(|_| ConnectionError::Storage)?,
                &bytes,
            )
            .map_err(|_| ConnectionError::Storage)
    }

    pub(crate) fn load_pending_stop(&self) -> Result<Option<PendingStop>, ConnectionError> {
        let path =
            RelativePath::parse("pending-stop.json").map_err(|_| ConnectionError::Storage)?;
        let bytes = match self.root.read_file(&path, 4096) {
            Ok(bytes) => bytes,
            Err(PlatformError::NotFound) => return Ok(None),
            Err(_) => return Err(ConnectionError::Storage),
        };
        let pending: PendingStop = decode_json(&bytes).map_err(|_| ConnectionError::Invalid)?;
        if !matches!(pending.state.as_str(), "pending" | "complete")
            || pending.pid == 0
            || pending.start_marker.is_empty()
            || pending.start_marker.len() > 128
            || pending.connection_binding.as_ref().is_some_and(|binding| {
                binding.len() != 64
                    || !binding
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            || pending.operation_id.is_some() != pending.receipt.is_some()
            || pending.receipt.as_ref().is_some_and(|receipt| {
                !receipt.accepted
                    || pending.operation_id.as_ref() != Some(&receipt.operation_id)
                    || receipt.target.kind != "engine"
                    || receipt.target.instance_id != pending.instance_id
            })
        {
            return Err(ConnectionError::Invalid);
        }
        Ok(Some(pending))
    }

    pub(crate) fn save_pending_stop(&self, pending: &PendingStop) -> Result<(), ConnectionError> {
        let bytes = serde_json::to_vec(pending).map_err(|_| ConnectionError::Invalid)?;
        self.root
            .write_atomic(
                &RelativePath::parse("pending-stop.json").map_err(|_| ConnectionError::Storage)?,
                &bytes,
            )
            .map_err(|_| ConnectionError::Storage)
    }

    pub(crate) fn connection(
        &self,
        data_root: &Path,
        probe_timeout: Duration,
        client_limits: ClientLimits,
    ) -> Result<DiscoveredEngine, ConnectionError> {
        let engine_root = OwnedRoot::open(data_root, RootPurpose::EngineData)
            .map_err(|_| ConnectionError::Unavailable)?;
        let verified =
            dissect3d_connection::verify_engine(&engine_root, probe_timeout).map_err(|error| {
                match error {
                    dissect3d_connection::ReadinessError::InvalidDiscovery => {
                        ConnectionError::Invalid
                    }
                    dissect3d_connection::ReadinessError::Incompatible => {
                        ConnectionError::Incompatible
                    }
                    dissect3d_connection::ReadinessError::Deadline
                    | dissect3d_connection::ReadinessError::Unavailable => {
                        ConnectionError::Unavailable
                    }
                }
            })?;
        Ok(DiscoveredEngine {
            discovery: verified.discovery,
            client_limits,
        })
    }
}

pub(crate) struct DiscoveredEngine {
    pub(crate) discovery: DiscoveryRecord,
    client_limits: ClientLimits,
}

impl DiscoveredEngine {
    pub(crate) fn client(
        &self,
        credential: impl Into<AccessCredential>,
    ) -> Result<Client, ConnectionError> {
        let credential = credential.into();
        if credential.installation_id != self.discovery.installation_id
            || credential.instance_id != self.discovery.instance_id
        {
            return Err(ConnectionError::Unauthorized);
        }
        let secret = decode_secret(&credential.secret_hex)?;
        let token = SecretToken::new(secret).map_err(|_| ConnectionError::Invalid)?;
        let pin: [u8; 32] = self
            .discovery
            .trust_anchor_sha256
            .as_slice()
            .try_into()
            .map_err(|_| ConnectionError::Invalid)?;
        Client::new(
            ConnectionMaterial::new(
                self.discovery.base_url.clone(),
                self.discovery.installation_id.clone(),
                self.discovery.instance_id.clone(),
                credential.client_id.clone(),
                self.discovery.trust_anchor_der.clone(),
                pin,
                token,
            ),
            self.client_limits,
        )
        .map_err(|_| ConnectionError::Invalid)
    }

    pub(crate) fn enroll(
        &self,
        credential: &ProfileCredential,
    ) -> Result<EnrollmentReceipt, ConnectionError> {
        self.enroll_with_kind(credential, "enroll")
    }

    pub(crate) fn enroll_submission(
        &self,
        credential: &ProfileCredential,
    ) -> Result<EnrollmentReceipt, ConnectionError> {
        self.enroll_with_kind(credential, "enroll_submission")
    }

    pub(crate) fn supports_submission_access(&self) -> Result<(), ConnectionError> {
        let endpoint = native_endpoint(&self.discovery.bootstrap_endpoint);
        let owner = current_owner_identity().map_err(|_| ConnectionError::Unavailable)?;
        let mut channel = connect_bootstrap(&endpoint, &owner, self.client_limits.connect_timeout)
            .map_err(|_| ConnectionError::Unavailable)?;
        let request = serde_json::json!({
            "kind": "capabilities",
            "bootstrap_version": "1.0",
            "instance_id": self.discovery.instance_id,
        });
        let encoded = serde_json::to_vec(&request).map_err(|_| ConnectionError::Invalid)?;
        channel
            .write_frame(&encoded)
            .map_err(|_| ConnectionError::Unavailable)?;
        let response = channel
            .read_frame()
            .map_err(|_| ConnectionError::Unavailable)?;
        let receipt = decode_capabilities_response(&response)?;
        if receipt.bootstrap_version != "1.0"
            || receipt.installation_id != self.discovery.installation_id
            || receipt.instance_id != self.discovery.instance_id
            || receipt.enrollment_policies != ["core-v1", "submission-v1"]
        {
            return Err(ConnectionError::Incompatible);
        }
        Ok(())
    }

    fn enroll_with_kind(
        &self,
        credential: &ProfileCredential,
        kind: &'static str,
    ) -> Result<EnrollmentReceipt, ConnectionError> {
        let endpoint = native_endpoint(&self.discovery.bootstrap_endpoint);
        let owner = current_owner_identity().map_err(|_| ConnectionError::Unavailable)?;
        let mut channel = connect_bootstrap(&endpoint, &owner, self.client_limits.connect_timeout)
            .map_err(|_| ConnectionError::Unavailable)?;
        let request = serde_json::json!({
            "kind": kind,
            "bootstrap_version": "1.0",
            "installation_id": credential.installation_id,
            "instance_id": credential.instance_id,
            "enrollment_id": credential.enrollment_id,
            "client_id": credential.client_id,
            "client_kind": "cli",
            "secret_hex": credential.secret_hex,
        });
        let mut encoded = serde_json::to_vec(&request).map_err(|_| ConnectionError::Invalid)?;
        let sent = channel.write_frame(&encoded);
        encoded.fill(0);
        sent.map_err(|_| ConnectionError::Unavailable)?;
        let mut response = channel
            .read_frame()
            .map_err(|_| ConnectionError::Unavailable)?;
        let receipt = decode_enrollment_response(&response);
        response.fill(0);
        let receipt: EnrollmentReceipt = receipt?;
        if receipt.bootstrap_version != "1.0"
            || receipt.installation_id != self.discovery.installation_id
            || receipt.client_id != credential.client_id
            || receipt.enrollment_id != credential.enrollment_id
        {
            return Err(ConnectionError::Incompatible);
        }
        Ok(receipt)
    }
}

fn native_endpoint(address: &BootstrapAddress) -> BootstrapEndpoint {
    match address {
        BootstrapAddress::Unix { path } => BootstrapEndpoint::Unix { path: path.into() },
        BootstrapAddress::WindowsPipe { name } => {
            BootstrapEndpoint::WindowsPipe { name: name.clone() }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapCapabilities {
    bootstrap_version: String,
    installation_id: InstallationId,
    instance_id: InstanceId,
    enrollment_policies: Vec<String>,
}

fn decode_capabilities_response(bytes: &[u8]) -> Result<BootstrapCapabilities, ConnectionError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Rejection {
        bootstrap_version: String,
        error: String,
    }
    if let Ok(rejection) = decode_json::<Rejection>(bytes) {
        if rejection.bootstrap_version != "1.0" {
            return Err(ConnectionError::Incompatible);
        }
        return Err(match rejection.error.as_str() {
            "invalid_request" => ConnectionError::Incompatible,
            "unauthorized" => ConnectionError::Unauthorized,
            _ => ConnectionError::Unavailable,
        });
    }
    decode_json(bytes).map_err(|_| ConnectionError::Incompatible)
}

fn decode_enrollment_response(bytes: &[u8]) -> Result<EnrollmentReceipt, ConnectionError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Rejection {
        bootstrap_version: String,
        error: String,
    }
    if let Ok(rejection) = decode_json::<Rejection>(bytes) {
        if rejection.bootstrap_version != "1.0" {
            return Err(ConnectionError::Incompatible);
        }
        return Err(match rejection.error.as_str() {
            "unauthorized" => ConnectionError::Unauthorized,
            "limit_reached" => ConnectionError::Capacity,
            "conflict" => ConnectionError::Conflict,
            "invalid_request" => ConnectionError::EnrollmentRejected,
            _ => ConnectionError::Unavailable,
        });
    }
    decode_json(bytes).map_err(|_| ConnectionError::Invalid)
}

fn decode_secret(encoded: &str) -> Result<Vec<u8>, ConnectionError> {
    if encoded.len() != 64 {
        return Err(ConnectionError::Invalid);
    }
    let mut secret = Vec::with_capacity(32);
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ConnectionError::Invalid);
    }
    for pair in pairs {
        let high = nibble(pair[0]).ok_or(ConnectionError::Invalid)?;
        let low = nibble(pair[1]).ok_or(ConnectionError::Invalid)?;
        secret.push(high << 4 | low);
    }
    Ok(secret)
}

fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_stop_records_without_receipts_remain_readable() {
        let pending: PendingStop = decode_json(
            br#"{"installation_id":"ins_0123456789abcdef0123456789abcdef","instance_id":"eng_1123456789abcdef0123456789abcdef","pid":42,"start_marker":"start","idempotency_key":"key_0123456789abcdef0123456789abcdef","state":"pending"}"#,
        )
        .expect("legacy pending-stop record");
        assert!(pending.operation_id.is_none());
        assert!(pending.receipt.is_none());
    }
}

#[cfg(test)]
mod enrollment_response_tests {
    use super::*;
    #[test]
    fn explicit_enrollment_rejection_is_distinct_from_a_lost_receipt() {
        for (code, expected) in [
            ("unauthorized", ConnectionError::Unauthorized),
            ("limit_reached", ConnectionError::Capacity),
            ("conflict", ConnectionError::Conflict),
            ("invalid_request", ConnectionError::EnrollmentRejected),
        ] {
            let bytes =
                serde_json::to_vec(&serde_json::json!({"bootstrap_version":"1.0", "error":code}))
                    .unwrap();
            assert!(matches!(decode_enrollment_response(&bytes), Err(error) if error == expected));
        }
        assert!(matches!(
            decode_enrollment_response(b"{"),
            Err(ConnectionError::Invalid)
        ));
    }
}

#[cfg(test)]
mod submission_enrollment_tests {
    use super::*;

    #[test]
    fn old_profiles_default_to_core_policy_and_pending_policy_is_retained() {
        let mut credential: ProfileCredential = decode_json(
            br#"{"installation_id":"ins_0123456789abcdef0123456789abcdef","instance_id":"eng_0123456789abcdef0123456789abcdef","client_id":"cli_0123456789abcdef0123456789abcdef","enrollment_id":"enr_0123456789abcdef0123456789abcdef","secret_hex":"abababababababababababababababababababababababababababababababab","state":"pending"}"#,
        )
        .expect("existing pending profile");
        assert!(!credential.submission_access);
        let core_record = serde_json::to_value(&credential).expect("core profile encoding");
        assert!(core_record.get("submission_access").is_none());

        credential.submission_access = true;
        let submission_record = serde_json::to_value(&credential).expect("pending policy encoding");
        assert_eq!(submission_record["submission_access"], true);
        let recovered: ProfileCredential = serde_json::from_value(submission_record)
            .expect("pending opt-in policy remains readable");
        assert!(recovered.submission_access);
    }

    #[test]
    fn old_peer_capability_rejection_is_classified_as_incompatible() {
        let response = serde_json::to_vec(
            &serde_json::json!({"bootstrap_version":"1.0","error":"invalid_request"}),
        )
        .unwrap();
        assert!(matches!(
            decode_capabilities_response(&response),
            Err(ConnectionError::Incompatible)
        ));
    }
}
