//! Internal credential records passed into the serialized store actor.
//!
//! These types mark the trust boundary between native transport verification
//! and durable authorization. Raw enrollment tokens are intentionally absent:
//! only the fixed-size digest crosses into the persistence layer.

use dissect3d_api::{ClientId, EnrollmentId, InstallationId, InstanceId, TokenDigest};
use dissect3d_platform::OwnerIdentity;

/// Enrollment after native peer verification and raw-token removal.
///
/// Fields are crate-private so external callers cannot claim a verified owner
/// or choose the engine identity to which a credential should be bound.
pub struct VerifiedEnrollment {
    pub(crate) owner: OwnerIdentity,
    pub(crate) installation_id: InstallationId,
    pub(crate) instance_id: InstanceId,
    pub(crate) enrollment_id: EnrollmentId,
    pub(crate) client_id: ClientId,
    pub(crate) token_digest: TokenDigest,
    pub(crate) grant_policy: GrantPolicy,
}

/// Closed set of enrollment policies accepted by this engine version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrantPolicy {
    CoreV1,
    SubmissionV1,
}

impl GrantPolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CoreV1 => "core-v1",
            Self::SubmissionV1 => "submission-v1",
        }
    }

    pub(crate) const fn grants(self) -> &'static [&'static str] {
        match self {
            Self::CoreV1 => &INITIAL_GRANTS,
            Self::SubmissionV1 => &SUBMISSION_GRANTS,
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "core-v1" => Some(Self::CoreV1),
            "submission-v1" => Some(Self::SubmissionV1),
            _ => None,
        }
    }
}

impl VerifiedEnrollment {
    pub fn new(
        owner: OwnerIdentity,
        installation_id: InstallationId,
        instance_id: InstanceId,
        enrollment_id: EnrollmentId,
        client_id: ClientId,
        token_digest: TokenDigest,
    ) -> Self {
        Self {
            owner,
            installation_id,
            instance_id,
            enrollment_id,
            client_id,
            token_digest,
            grant_policy: GrantPolicy::CoreV1,
        }
    }

    /// Native bootstrap's explicit, capability-gated enrollment path.
    ///
    /// Keeping this constructor crate-controlled prevents API consumers from
    /// selecting a wider grant set without passing through native verification.
    pub(crate) fn new_submission_access(
        owner: OwnerIdentity,
        installation_id: InstallationId,
        instance_id: InstanceId,
        enrollment_id: EnrollmentId,
        client_id: ClientId,
        token_digest: TokenDigest,
    ) -> Self {
        Self {
            owner,
            installation_id,
            instance_id,
            enrollment_id,
            client_id,
            token_digest,
            grant_policy: GrantPolicy::SubmissionV1,
        }
    }
}

/// Active client context reconstructed only after actor-side verification.
///
/// Its private construction path prevents a request payload from inventing an
/// authenticated identity or widening its grants.
#[derive(Clone)]
pub struct AuthContext {
    pub(crate) installation_id: InstallationId,
    pub(crate) client_id: ClientId,
    pub(crate) granted_operations: Vec<String>,
}

impl AuthContext {
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn granted_operations(&self) -> &[String] {
        &self.granted_operations
    }
}

pub(crate) const INITIAL_GRANTS: [&str; 5] = [
    "auth.revoke_self",
    "auth.status",
    "engine.info",
    "engine.shutdown",
    "operation.show_own",
];

pub(crate) const SUBMISSION_GRANTS: [&str; 9] = [
    "auth.revoke_self",
    "auth.status",
    "engine.info",
    "engine.shutdown",
    "inputs.create",
    "jobs.list",
    "jobs.show",
    "jobs.submit",
    "operation.show_own",
];
