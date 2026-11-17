//! Versioned native execution authority exchange; independent of dispatch readiness.
use crate::{ClientId, InstallationId, InstanceId, ValidationError};
use serde::{Deserialize, Serialize};
pub const EXECUTION_AUTHORIZATION_CONTRACT: &str = "execution-v1";
pub const EXECUTION_GRANTS: [&str; 15] = [
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnrollmentCapability {
    pub bootstrap_version: String,
    pub contract_version: String,
    pub installation_id: InstallationId,
    pub instance_id: InstanceId,
    pub enrollment_policies: Vec<String>,
    pub authorization_operations: Vec<String>,
}
impl ExecutionEnrollmentCapability {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.bootstrap_version != "1.0"
            || self.contract_version != EXECUTION_AUTHORIZATION_CONTRACT
            || self.enrollment_policies != [EXECUTION_AUTHORIZATION_CONTRACT]
            || self.authorization_operations != ["enroll_execution", "authorize_execution"]
        {
            return Err(ValidationError);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAuthorizationReceipt {
    pub bootstrap_version: String,
    pub contract_version: String,
    pub installation_id: InstallationId,
    pub client_id: ClientId,
    pub authorization_id: String,
    pub grant_policy: String,
    pub granted_operations: Vec<String>,
    pub replayed: bool,
}
impl ExecutionAuthorizationReceipt {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let valid = self.authorization_id.strip_prefix("aut_").is_some_and(|v| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !valid
            || self.bootstrap_version != "1.0"
            || self.contract_version != EXECUTION_AUTHORIZATION_CONTRACT
            || self.grant_policy != EXECUTION_AUTHORIZATION_CONTRACT
            || self.granted_operations != EXECUTION_GRANTS
        {
            return Err(ValidationError);
        }
        Ok(())
    }
}
