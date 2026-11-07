//! Wire identity, credential and error records shared between the CLI and engine.
//!
//! These types validate values at the boundary so callers do not have to
//! repeat identifier, timestamp, or secret-length checks after deserialization.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid value")]
pub struct ValidationError;

macro_rules! identifier {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parse a fixed-prefix identifier with 128 bits of lowercase hex entropy.
            ///
            /// Requiring one canonical spelling keeps persisted keys and wire
            /// comparisons stable across clients.
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                let Some(suffix) = value.strip_prefix($prefix) else {
                    return Err(ValidationError);
                };
                if suffix.len() != 32
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ValidationError);
                }
                Ok(Self(value))
            }

            /// Return the stable wire representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(InstallationId, "ins_");
identifier!(InstanceId, "eng_");
identifier!(ClientId, "cli_");
identifier!(EnrollmentId, "enr_");
identifier!(OperationId, "op_");
identifier!(CorrelationId, "corr_");

/// Receipt returned after a durable enrollment commit or exact replay.
///
/// `replayed` distinguishes an idempotent retry from a newly committed
/// enrollment without changing the stable identity or grant set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentReceipt {
    pub bootstrap_version: String,
    pub installation_id: InstallationId,
    pub client_id: ClientId,
    pub enrollment_id: EnrollmentId,
    pub granted_operations: Vec<String>,
    pub created_at_ms: TimestampMs,
    pub replayed: bool,
}

/// Receipt returned after a client's own revocation commits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReceipt {
    pub api_version: String,
    pub client_id: ClientId,
    pub revoked: bool,
    pub revoked_at_ms: TimestampMs,
}

/// Current non-inference engine facts returned only to an authorized client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineInfo {
    pub api_version: String,
    pub engine_version: String,
    pub installation_id: InstallationId,
    pub instance_id: InstanceId,
    pub phase: EnginePhase,
    pub supported_operations: Vec<String>,
    pub granted_operations: Vec<String>,
    pub required_features: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    /// Source of all engine-owned effective limits; absent on older peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits_source: Option<String>,
    pub platform: PlatformInfo,
    /// Optional read-only catalog capability, ignored by older core clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<crate::DiscoveryCapability>,
    /// Optional queued-submission capability, absent on older or inactive engines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<SubmissionCapability>,
}

/// Versioned, optional Stage 3 capability advertised only by an active composition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionCapability {
    pub version: String,
    pub dispatch_enabled: bool,
    pub operations: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    pub limits_source: String,
}

/// Service lifecycle state exposed by engine inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnginePhase {
    Ready,
    Stopping,
}

/// Native platform facts are descriptive and do not assert model support.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub architecture: String,
}

/// Active client's own authenticated access and fixed grants.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatus {
    pub api_version: String,
    pub installation_id: InstallationId,
    pub instance_id: InstanceId,
    pub client_id: ClientId,
    pub active: bool,
    pub granted_operations: Vec<String>,
}

/// Closed versioned body for an own-client revocation request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRevokeRequest {
    pub api_version: String,
    pub required_features: Vec<String>,
}

/// Closed target for a public engine operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTarget {
    pub kind: String,
    pub instance_id: InstanceId,
}

/// Empty, closed options record for the core shutdown operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownOptions {}

/// Closed request for the only operation kind implemented by this slice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownRequest {
    pub api_version: String,
    pub kind: String,
    pub target: OperationTarget,
    pub options: ShutdownOptions,
    pub required_features: Vec<String>,
}

/// Durable receipt for a newly accepted or exactly replayed operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReceipt {
    pub api_version: String,
    pub accepted: bool,
    pub operation_id: OperationId,
    pub target: OperationTarget,
    pub state: OperationState,
    pub replayed: bool,
}

/// Creator-only view of a durable core operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSnapshot {
    pub api_version: String,
    pub operation_id: OperationId,
    pub kind: String,
    pub target: OperationTarget,
    pub state: OperationState,
    pub phase: String,
    pub created_at_ms: TimestampMs,
    pub updated_at_ms: TimestampMs,
    pub error: Option<String>,
}

/// Persisted lifecycle state of a bounded core operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Interrupted,
}

/// Native process identity used only for safe startup/exit observation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReference {
    pub pid: u32,
    pub start_marker: String,
}

/// Native bootstrap endpoint. The wire type cannot represent a general URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootstrapAddress {
    Unix { path: String },
    WindowsPipe { name: String },
}

/// Protected, nonsecret descriptor published after all service listeners are ready.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRecord {
    pub discovery_version: String,
    pub installation_id: InstallationId,
    pub instance_id: InstanceId,
    pub base_url: String,
    pub bootstrap_endpoint: BootstrapAddress,
    pub process: ProcessReference,
    pub trust_anchor_der: Vec<u8>,
    pub trust_anchor_sha256: Vec<u8>,
}

/// A bounded client-generated idempotency key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validate the accepted ASCII key alphabet and length.
    pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        {
            return Err(ValidationError);
        }
        Ok(Self(value))
    }

    /// Return the stable wire representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Nonnegative UTC milliseconds used for observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TimestampMs(u64);

impl TimestampMs {
    /// Construct a timestamp representable by the signed wire/database range.
    pub fn new(value: u64) -> Result<Self, ValidationError> {
        if value > i64::MAX as u64 {
            return Err(ValidationError);
        }
        Ok(Self(value))
    }

    /// Return milliseconds since the Unix epoch.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for TimestampMs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Secret bytes that never appear in normal debug output.
///
/// The API transports the raw token only where enrollment requires it; the
/// engine should convert it to a digest before persistence.
pub struct SecretToken(Vec<u8>);

impl SecretToken {
    /// Own an exactly 32-byte enrollment secret.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.len() != 32 {
            return Err(ValidationError);
        }
        Ok(Self(bytes))
    }

    /// Borrow bytes for explicit credential transport or digesting.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

/// SHA-256 digest of an enrollment secret; raw tokens are never persisted.
///
/// Debug output is redacted because digests still participate in credential
/// verification and should not be copied into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// Construct from a fixed-size digest.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the digest for constant-time comparison or persistence.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenDigest([REDACTED])")
    }
}
