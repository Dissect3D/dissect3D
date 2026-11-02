//! Versioned shared records and strict JSON decoding for local engine clients.
//!
//! This crate contains transport-neutral contracts only. It does not own
//! service state or translate private platform/SQLite failures into wire data.
#![forbid(unsafe_code)]

#[cfg(feature = "client")]
mod client;
mod decode;
mod discovery;
mod error;
mod types;

#[cfg(feature = "client")]
pub use client::{Client, ClientError, ClientLimits, ConnectionMaterial};
pub use decode::{DecodeError, decode_json};
pub use discovery::{
    DiscoveryCapability, DiscoveryObservation, EligibilityObservation, EvidenceObservation,
    ExecutionAuthorizationObservation, InstallationObservation, InventoryDetail, InventoryPage,
    LoadedObservation, ModelDetail, ModelListQuery, ModelLookup, ModelSummary, ObservationReason,
    ObservationScope, PageQuery, ReadinessObservation, RuntimeDetail, RuntimeLookup,
    RuntimeSummary, SchemaAttachment, TaskBindingDetail, TaskDetail, TaskKey, TaskListQuery,
    TaskLookup, TaskSummary,
};
pub use error::{ApiError, ApiErrorBody, ErrorCode};
pub use types::{
    AuthRevokeRequest, AuthStatus, BootstrapAddress, ClientId, CorrelationId, DiscoveryRecord,
    EngineInfo, EnginePhase, EnrollmentId, EnrollmentReceipt, IdempotencyKey, InstallationId,
    InstanceId, OperationId, OperationReceipt, OperationSnapshot, OperationState, OperationTarget,
    PlatformInfo, ProcessReference, RevocationReceipt, SecretToken, ShutdownOptions,
    ShutdownRequest, TimestampMs, TokenDigest, ValidationError,
};
