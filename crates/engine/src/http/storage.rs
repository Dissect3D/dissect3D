//! Authenticated creator-scoped storage usage and engine capacity facts
//! (`GET /v1/storage`, `RP-004`, `RP-005`).

use super::{AuthorizedRequest, ServiceState, access};
use crate::CoreError;
use crate::domain::{input_policy, publication_policy};
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use dissect3d_api::{
    ErrorCode, StorageMeasurement, StorageMeasurementStatus, StorageSnapshot, StorageUsage,
};
use std::collections::BTreeMap;
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new().route("/v1/storage", get(show))
}

async fn show(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    if request.uri().query().is_some() || access::has_unsupported_read_headers(request.headers()) {
        return access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    let store = state.store.clone();
    let root = state.diagnostic_root.clone();
    let result = tokio::task::spawn_blocking(move || {
        let usage = store.creator_storage_usage(authorized.context);
        let available_space = root.available_space_bytes().ok();
        (usage, available_space)
    })
    .await;
    let (usage_result, available_space) = match result {
        Ok(pair) => pair,
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StoreUnavailable,
                true,
            );
        }
    };
    let mut limits = enforced_limits();
    if let Some(available) = available_space {
        limits.insert("available_space_bytes".to_owned(), available);
    }
    let snapshot = match usage_result {
        Ok(usage) => {
            let status = if available_space.is_some() {
                StorageMeasurementStatus::Current
            } else {
                StorageMeasurementStatus::Stale
            };
            StorageSnapshot {
                api_version: "1.0".to_owned(),
                storage_contract: "rp-0.1".to_owned(),
                usage: StorageUsage {
                    retained_input_bytes: Some(usage.retained_input_bytes),
                    published_output_bytes: Some(usage.published_output_bytes),
                    private_staging_bytes: Some(usage.private_staging_bytes),
                    metadata_bytes: Some(usage.metadata_bytes),
                },
                limits,
                measurement: StorageMeasurement {
                    status,
                    measured_at_ms: Some(usage.measured_at_ms),
                },
            }
        }
        Err(CoreError::Unauthorized) => {
            return access::error_response(
                StatusCode::UNAUTHORIZED,
                ErrorCode::Unauthorized,
                false,
            );
        }
        Err(CoreError::Busy) => {
            return access::error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true);
        }
        Err(CoreError::StoreIncompatible) => {
            return access::error_response(
                StatusCode::CONFLICT,
                ErrorCode::StoreIncompatible,
                false,
            );
        }
        Err(_) => StorageSnapshot {
            api_version: "1.0".to_owned(),
            storage_contract: "rp-0.1".to_owned(),
            usage: StorageUsage {
                retained_input_bytes: None,
                published_output_bytes: None,
                private_staging_bytes: None,
                metadata_bytes: None,
            },
            limits,
            measurement: StorageMeasurement {
                status: StorageMeasurementStatus::Unavailable,
                measured_at_ms: None,
            },
        },
    };
    Json(snapshot).into_response()
}

fn enforced_limits() -> BTreeMap<String, u64> {
    [
        ("input_bytes_max", input_policy::MAX_INPUT_BYTES),
        (
            "staging_reserved_bytes_max",
            input_policy::MAX_STAGING_BYTES,
        ),
        (
            "artifact_bytes_per_attempt_max",
            publication_policy::ARTIFACT_BYTES_PER_ATTEMPT_MAX,
        ),
        (
            "manifest_bytes_per_attempt_max",
            publication_policy::MANIFEST_BYTES_PER_ATTEMPT_MAX,
        ),
        (
            "result_private_bytes_max",
            publication_policy::PRIVATE_BYTES_MAX,
        ),
        (
            "result_published_bytes_max",
            publication_policy::PUBLISHED_BYTES_MAX,
        ),
        ("result_records_max", publication_policy::RESULT_RECORDS_MAX),
        (
            "storage_free_reserve_bytes",
            publication_policy::STORAGE_FREE_RESERVE_BYTES,
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}
