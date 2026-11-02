//! Safe public error envelopes; private error sources remain in their owning crate.
//!
//! The wire representation deliberately carries stable categories and bounded
//! context only. Callers can correlate and retry a failure without receiving
//! filesystem paths, SQL diagnostics, or other internal source strings.

use serde::{Deserialize, Serialize};

use crate::{CorrelationId, OperationId};

/// Safe machine-readable core error codes for the `/v1` foundation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Forbidden,
    OriginDenied,
    HostDenied,
    InvalidRequest,
    IdempotencyConflict,
    StoreIncompatible,
    TransferLimit,
    EngineRecovering,
    PersistenceUnavailable,
    StorageUnavailable,
    RequiredFeatureUnsupported,
    IncompatibleContract,
    OperationUnavailable,
    NotFound,
    AmbiguousSelection,
    InventoryCursorExpired,
    Busy,
}

/// Bounded public error details. Fields contain categories, never source strings.
/// `details` is reserved for explicitly approved structured fields, not an
/// arbitrary serialization of an internal error.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub correlation_id: CorrelationId,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Versioned safe error envelope returned by the local control API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub api_version: String,
    pub error: ApiErrorBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
}
