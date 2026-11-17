//! Native execution authority helpers. WE-P08 owns their user-command wiring.
use super::*;
use dissect3d_api::{
    EXECUTION_AUTHORIZATION_CONTRACT, EXECUTION_GRANTS, ExecutionAuthorizationReceipt,
    ExecutionEnrollmentCapability,
};
const PENDING_FILE: &str = "execution-authorization.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingExecutionAuthorization {
    pub(super) record_version: String,
    pub(super) installation_id: InstallationId,
    pub(super) client_id: ClientId,
    pub(super) authorization_id: String,
    pub(super) grant_policy: String,
    pub(super) state: String,
}
impl PendingExecutionAuthorization {
    fn validate(&self) -> Result<(), ConnectionError> {
        let valid = self.authorization_id.strip_prefix("aut_").is_some_and(|s| {
            s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !valid
            || self.record_version != "1.0"
            || self.grant_policy != EXECUTION_AUTHORIZATION_CONTRACT
            || !matches!(self.state.as_str(), "pending" | "complete")
        {
            return Err(ConnectionError::Invalid);
        }
        Ok(())
    }
}
/// Native execution-authority records and exchanges are fail-closed on Windows
/// until ordinary-user namespace durability is established.
fn require_native_authority() -> Result<(), ConnectionError> {
    if cfg!(windows) {
        Err(ConnectionError::Incompatible)
    } else {
        Ok(())
    }
}
impl Profile {
    fn read_execution_authorization(
        &self,
    ) -> Result<Option<PendingExecutionAuthorization>, ConnectionError> {
        let path = RelativePath::parse(PENDING_FILE).map_err(|_| ConnectionError::Storage)?;
        let bytes = match self.root.read_file(&path, 4096) {
            Ok(b) => b,
            Err(PlatformError::NotFound) => return Ok(None),
            Err(_) => return Err(ConnectionError::Storage),
        };
        let pending: PendingExecutionAuthorization =
            decode_json(&bytes).map_err(|_| ConnectionError::Invalid)?;
        pending.validate()?;
        Ok(Some(pending))
    }
    fn write_execution_authorization(
        &self,
        pending: &PendingExecutionAuthorization,
    ) -> Result<(), ConnectionError> {
        pending.validate()?;
        let bytes = serde_json::to_vec(pending).map_err(|_| ConnectionError::Invalid)?;
        if bytes.len() > 4096 {
            return Err(ConnectionError::Capacity);
        }
        self.root
            .write_recovery_record(
                &RelativePath::parse(PENDING_FILE).map_err(|_| ConnectionError::Storage)?,
                &bytes,
            )
            .map_err(|_| ConnectionError::Storage)
    }
    /// Requires this profile's control lease across load/save/transport, and the
    /// credential loaded under that lease. Completed records retain their replay
    /// ID; repeated success cannot grow SQL history.
    ///
    /// A record for this credential's installation/client, pending or complete,
    /// is never discarded, even when the credential is revoked. A record for a
    /// different installation/client is superseded only by an `active`
    /// credential: one durable recovery-record write replaces it with a new
    /// pending record, so the old ID never reaches a send path.
    fn begin_execution_authorization(
        &self,
        lease: &ControlLease<'_>,
        credential: &ProfileCredential,
    ) -> Result<PendingExecutionAuthorization, ConnectionError> {
        lease.require(self)?;
        require_native_authority()?;
        if let Some(pending) = self.read_execution_authorization()? {
            if pending.installation_id == credential.installation_id
                && pending.client_id == credential.client_id
            {
                // A prior rename may have been visible even though its durability
                // barrier failed. Re-establish the barrier for this exact ID before send.
                self.write_execution_authorization(&pending)?;
                return Ok(pending);
            }
            if credential.state != "active" {
                return Err(ConnectionError::Conflict);
            }
        }
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| ConnectionError::Storage)?;
        let authorization_id = format!(
            "aut_{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let pending = PendingExecutionAuthorization {
            record_version: "1.0".into(),
            installation_id: credential.installation_id.clone(),
            client_id: credential.client_id.clone(),
            authorization_id,
            grant_policy: EXECUTION_AUTHORIZATION_CONTRACT.into(),
            state: "pending".into(),
        };
        self.write_execution_authorization(&pending)?;
        Ok(pending)
    }
    /// Own the permanent profile lease across credential load, recovery, durable
    /// preparation, transport and acknowledgement. A caller that already holds the
    /// lease passes its proof; otherwise this acquires it. A failed or abandoned
    /// reply retains the ID.
    pub(crate) fn with_execution_authorization(
        &self,
        held: Option<&ControlLease<'_>>,
        send: impl FnOnce(
            &ProfileCredential,
            &PendingExecutionAuthorization,
        ) -> Result<ExecutionAuthorizationReceipt, ConnectionError>,
    ) -> Result<ExecutionAuthorizationReceipt, ConnectionError> {
        let acquired;
        let lease = match held {
            Some(lease) => lease,
            None => {
                acquired = self.control_lease()?;
                &acquired
            }
        };
        lease.require(self)?;
        let credential = self.load()?.ok_or(ConnectionError::Unauthorized)?;
        let pending = self.begin_execution_authorization(lease, &credential)?;
        let receipt = send(&credential, &pending)?;
        self.complete_execution_authorization(lease, &receipt)?;
        Ok(receipt)
    }
    fn complete_execution_authorization(
        &self,
        lease: &ControlLease<'_>,
        receipt: &ExecutionAuthorizationReceipt,
    ) -> Result<(), ConnectionError> {
        lease.require(self)?;
        require_native_authority()?;
        receipt.validate().map_err(|_| ConnectionError::Invalid)?;
        let mut pending = self
            .read_execution_authorization()?
            .ok_or(ConnectionError::Conflict)?;
        if pending.installation_id != receipt.installation_id
            || pending.client_id != receipt.client_id
            || pending.authorization_id != receipt.authorization_id
        {
            return Err(ConnectionError::Conflict);
        }
        pending.state = "complete".into();
        self.write_execution_authorization(&pending)
    }
}
#[derive(Serialize)]
struct EnrollmentRequest<'a> {
    kind: &'static str,
    bootstrap_version: &'static str,
    execution_contract: &'static str,
    installation_id: &'a InstallationId,
    instance_id: &'a InstanceId,
    enrollment_id: &'a EnrollmentId,
    client_id: &'a ClientId,
    client_kind: &'static str,
    secret_hex: &'a str,
}
#[derive(Serialize)]
struct AuthorizationRequest<'a> {
    kind: &'static str,
    bootstrap_version: &'static str,
    execution_contract: &'static str,
    installation_id: &'a InstallationId,
    instance_id: &'a InstanceId,
    client_id: &'a ClientId,
    authorization_id: &'a str,
    secret_hex: &'a str,
}
impl DiscoveredEngine {
    fn execution_exchange<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R, ConnectionError> {
        require_native_authority()?;
        let endpoint = native_endpoint(&self.discovery.bootstrap_endpoint);
        let owner = current_owner_identity().map_err(|_| ConnectionError::Unavailable)?;
        let mut channel = connect_bootstrap(&endpoint, &owner, self.client_limits.connect_timeout)
            .map_err(|_| ConnectionError::Unavailable)?;
        let mut bytes = serde_json::to_vec(request).map_err(|_| ConnectionError::Invalid)?;
        if bytes.len() > 16_384 {
            bytes.fill(0);
            return Err(ConnectionError::Capacity);
        }
        let sent = channel.write_frame(&bytes);
        bytes.fill(0);
        sent.map_err(|_| ConnectionError::Unavailable)?;
        let mut response = channel
            .read_frame()
            .map_err(|_| ConnectionError::Unavailable)?;
        let result = decode_native_response(&response);
        response.fill(0);
        result
    }
    pub(crate) fn supports_execution_access(&self) -> Result<(), ConnectionError> {
        let receipt:ExecutionEnrollmentCapability=self.execution_exchange(&serde_json::json!({"kind":"execution_capabilities","bootstrap_version":"1.0","instance_id":self.discovery.instance_id})).map_err(|e|if e==ConnectionError::EnrollmentRejected {ConnectionError::Incompatible}else{e})?;
        receipt
            .validate()
            .map_err(|_| ConnectionError::Incompatible)?;
        if receipt.installation_id != self.discovery.installation_id
            || receipt.instance_id != self.discovery.instance_id
        {
            return Err(ConnectionError::Incompatible);
        }
        Ok(())
    }
    pub(crate) fn enroll_execution(
        &self,
        credential: &ProfileCredential,
    ) -> Result<EnrollmentReceipt, ConnectionError> {
        self.supports_execution_access()?;
        self.check_execution_credential(credential, false)?;
        let receipt: EnrollmentReceipt = self.execution_exchange(&EnrollmentRequest {
            kind: "enroll_execution",
            bootstrap_version: "1.0",
            execution_contract: EXECUTION_AUTHORIZATION_CONTRACT,
            installation_id: &credential.installation_id,
            instance_id: &credential.instance_id,
            enrollment_id: &credential.enrollment_id,
            client_id: &credential.client_id,
            client_kind: "cli",
            secret_hex: &credential.secret_hex,
        })?;
        if receipt.bootstrap_version != "1.0"
            || receipt.installation_id != credential.installation_id
            || receipt.client_id != credential.client_id
            || receipt.enrollment_id != credential.enrollment_id
            || receipt.granted_operations != EXECUTION_GRANTS
        {
            return Err(ConnectionError::Invalid);
        }
        Ok(receipt)
    }
    pub(crate) fn authorize_execution(
        &self,
        credential: &ProfileCredential,
        pending: &PendingExecutionAuthorization,
    ) -> Result<ExecutionAuthorizationReceipt, ConnectionError> {
        self.supports_execution_access()?;
        self.check_execution_credential(credential, true)?;
        pending.validate()?;
        if pending.installation_id != credential.installation_id
            || pending.client_id != credential.client_id
        {
            return Err(ConnectionError::Conflict);
        }
        let receipt: ExecutionAuthorizationReceipt =
            self.execution_exchange(&AuthorizationRequest {
                kind: "authorize_execution",
                bootstrap_version: "1.0",
                execution_contract: EXECUTION_AUTHORIZATION_CONTRACT,
                installation_id: &credential.installation_id,
                instance_id: &credential.instance_id,
                client_id: &credential.client_id,
                authorization_id: &pending.authorization_id,
                secret_hex: &credential.secret_hex,
            })?;
        receipt.validate().map_err(|_| ConnectionError::Invalid)?;
        if receipt.installation_id != credential.installation_id
            || receipt.client_id != credential.client_id
            || receipt.authorization_id != pending.authorization_id
        {
            return Err(ConnectionError::Invalid);
        }
        Ok(receipt)
    }
    fn check_execution_credential(
        &self,
        c: &ProfileCredential,
        active: bool,
    ) -> Result<(), ConnectionError> {
        if c.installation_id != self.discovery.installation_id
            || c.instance_id != self.discovery.instance_id
            || (active && c.state != "active")
            || c.state == "revoked"
        {
            return Err(ConnectionError::Unauthorized);
        }
        let mut secret = decode_secret(&c.secret_hex)?;
        secret.fill(0);
        Ok(())
    }
}
pub(super) fn decode_execution_authorization_receipt(
    bytes: &[u8],
) -> Result<ExecutionAuthorizationReceipt, ConnectionError> {
    let receipt: ExecutionAuthorizationReceipt = decode_native_response(bytes)?;
    receipt.validate().map_err(|_| ConnectionError::Invalid)?;
    Ok(receipt)
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod execution_tests;
#[cfg(all(test, unix))]
#[path = "authorization_recovery_tests.rs"]
mod recovery_tests;
