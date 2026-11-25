//! Creator-private HTTP routes for committed results, manifests, and streamed
//! artifact bytes (`RP-004`).
//!
//! Handlers stay thin: validate request framing/headers, delegate metadata
//! reads to the serialized `Store` actor and file verification to
//! `publication::storage::read_committed` on blocking threads, and map internal
//! failures once to safe public error codes.

use super::{AuthorizedRequest, ServiceState, access};
use crate::CoreError;
use crate::publication::storage::{ArtifactFault, check_result_availability, read_committed};
use crate::store::results::generated_name;
use axum::body::Body;
use axum::extract::{Extension, Path, Request, State};
use axum::http::StatusCode;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, HeaderName, HeaderValue,
};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use dissect3d_api::{ErrorCode, MANIFEST_BYTES_MAX, ResultsQuery, validate_result_filename};
use std::sync::Arc;

const ARTIFACT_STREAM_CHUNK_BYTES: usize = 65_536;
const X_CONTENT_SHA256: HeaderName = HeaderName::from_static("x-content-sha256");

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new()
        .route("/v1/results", get(list))
        .route("/v1/results/{result_id}/manifest", get(manifest))
        .route("/v1/artifacts/{artifact_id}", get(artifact))
}

async fn list(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    if access::has_unsupported_read_headers(request.headers()) {
        return access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    let query =
        match super::discovery::query_params(request.uri().query(), &["limit", "cursor"], 4096)
            .and_then(|params| super::discovery::page_query(&params))
        {
            Ok(page) => ResultsQuery {
                limit: page.limit,
                cursor: page.cursor,
            },
            Err(_) => {
                return access::error_response(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidRequest,
                    false,
                );
            }
        };
    let store = state.store.clone();
    let raw = match tokio::task::spawn_blocking(move || {
        store.list_results_raw(authorized.context, query)
    })
    .await
    {
        Ok(Ok(raw)) => raw,
        Ok(Err(problem)) => return super::jobs::error(problem),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StoreUnavailable,
                true,
            );
        }
    };
    let root = state.diagnostic_root.clone();
    let page = match tokio::task::spawn_blocking(move || {
        let availabilities = raw
            .rows
            .iter()
            .map(|row| check_result_availability(&root, &row.files))
            .collect::<Vec<_>>();
        raw.pack(&availabilities)
    })
    .await
    {
        Ok(Ok(page)) => page,
        Ok(Err(problem)) => return super::jobs::error(problem),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StorageUnavailable,
                true,
            );
        }
    };
    Json(page).into_response()
}

async fn manifest(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(result_id): Path<String>,
    request: Request<Body>,
) -> Response {
    if request.uri().query().is_some() || access::has_unsupported_read_headers(request.headers()) {
        return access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    if !generated_name(&result_id, "res_") {
        return access::error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, false);
    }
    let store = state.store.clone();
    let stored = match tokio::task::spawn_blocking(move || {
        store.result_manifest_file(authorized.context, result_id)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(error)) => return map_store_error(error),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StoreUnavailable,
                true,
            );
        }
    };
    if stored.file.byte_length > MANIFEST_BYTES_MAX as u64 {
        return access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        );
    }
    let root = state.diagnostic_root.clone();
    let file = stored.file.clone();
    let bytes = match tokio::task::spawn_blocking(move || read_committed(&root, &file)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(fault)) => return map_artifact_fault(fault),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StorageUnavailable,
                true,
            );
        }
    };
    let digest = hex_sha256(&stored.file.sha256);
    let Ok(length_header) = HeaderValue::from_str(&bytes.len().to_string()) else {
        return access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        );
    };
    let Ok(digest_header) = HeaderValue::from_str(&digest) else {
        return access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        );
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_LENGTH, length_header);
    headers.insert(X_CONTENT_SHA256, digest_header);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn artifact(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(artifact_id): Path<String>,
    request: Request<Body>,
) -> Response {
    if request.uri().query().is_some() || access::has_unsupported_read_headers(request.headers()) {
        return access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    if !generated_name(&artifact_id, "art_") {
        return access::error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, false);
    }
    let store = state.store.clone();
    let auth_for_lookup = authorized.context.clone();
    let stored = match tokio::task::spawn_blocking(move || {
        store.result_artifact_file(auth_for_lookup, artifact_id)
    })
    .await
    {
        Ok(Ok(stored)) => stored,
        Ok(Err(error)) => return map_store_error(error),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StoreUnavailable,
                true,
            );
        }
    };
    if validate_result_filename(&stored.filename).is_err() || !safe_media_type(&stored.media_type) {
        return access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        );
    }
    // Verify committed length and SHA-256 before sending headers so missing or
    // corrupted bytes return 410/503 cleanly with zero TOCTOU drift.
    let root = state.diagnostic_root.clone();
    let file = stored.file.clone();
    let bytes = match tokio::task::spawn_blocking(move || read_committed(&root, &file)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(fault)) => return map_artifact_fault(fault),
        Err(_) => {
            return access::error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StorageUnavailable,
                true,
            );
        }
    };
    let digest = hex_sha256(&stored.file.sha256);
    let disposition = format!("attachment; filename=\"{}\"", stored.filename);
    let (Ok(content_type), Ok(content_length), Ok(digest_header), Ok(disposition_header)) = (
        HeaderValue::from_str(&stored.media_type),
        HeaderValue::from_str(&bytes.len().to_string()),
        HeaderValue::from_str(&digest),
        HeaderValue::from_str(&disposition),
    ) else {
        return access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        );
    };
    // Backpressure-aware 64 KiB stream with zero background tasks: dropping
    // the connection drops the stream immediately. Active delivery re-checks
    // credential revocation between chunks so revoked clients stop at bounded
    // boundaries (`RP-004`).
    let stream = artifact_body_stream(bytes, state.store.clone(), authorized.context);
    let mut response = Response::new(Body::from_stream(stream));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, content_type);
    headers.insert(CONTENT_LENGTH, content_length);
    headers.insert(X_CONTENT_SHA256, digest_header);
    headers.insert(CONTENT_DISPOSITION, disposition_header);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn artifact_body_stream(
    bytes: Vec<u8>,
    store: Arc<crate::Store>,
    auth: crate::AuthContext,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
    let stream_state = StreamState {
        bytes,
        offset: 0,
        store,
        auth,
    };
    futures_util::stream::unfold(stream_state, |mut state| async move {
        if state.offset >= state.bytes.len() {
            return None;
        }
        if state.offset > 0 {
            let store = state.store.clone();
            let auth = state.auth.clone();
            let active = tokio::task::spawn_blocking(move || {
                store.check_active_grant(auth, "artifacts.read")
            })
            .await;
            if !matches!(active, Ok(Ok(()))) {
                state.offset = state.bytes.len();
                return Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "credential revoked",
                    )),
                    state,
                ));
            }
        }
        let end = state
            .offset
            .saturating_add(ARTIFACT_STREAM_CHUNK_BYTES)
            .min(state.bytes.len());
        let chunk = axum::body::Bytes::copy_from_slice(&state.bytes[state.offset..end]);
        state.offset = end;
        Some((Ok(chunk), state))
    })
}

struct StreamState {
    bytes: Vec<u8>,
    offset: usize,
    store: Arc<crate::Store>,
    auth: crate::AuthContext,
}

fn map_artifact_fault(fault: ArtifactFault) -> Response {
    match fault {
        ArtifactFault::Unavailable => {
            access::error_response(StatusCode::GONE, ErrorCode::ArtifactUnavailable, false)
        }
        ArtifactFault::Integrity => access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        ),
    }
}

pub(super) fn map_store_error(error: CoreError) -> Response {
    let (status, code, retryable) = match error {
        CoreError::Unauthorized => (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false),
        CoreError::NotFound => (StatusCode::NOT_FOUND, ErrorCode::NotFound, false),
        CoreError::Busy => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true),
        CoreError::InvalidStore => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        ),
        CoreError::StoreIncompatible => (StatusCode::CONFLICT, ErrorCode::StoreIncompatible, false),
        CoreError::Platform(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageUnavailable,
            true,
        ),
        CoreError::StoreUnavailable | CoreError::Conflict | CoreError::LimitReached => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StoreUnavailable,
            true,
        ),
        CoreError::CapacityExceeded(limit) => return access::capacity_response(limit),
    };
    access::error_response(status, code, retryable)
}

fn safe_media_type(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('/') else {
        return false;
    };
    !major.is_empty()
        && !minor.is_empty()
        && !minor.contains('/')
        && major
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b))
        && minor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b))
}

fn hex_sha256(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
#[path = "results_tests.rs"]
mod tests;
