//! HTTP framing and response adaptation for engine-owned input capture.

use super::{AuthorizedRequest, ServiceState};
use crate::inputs::InputError;
use crate::inputs::policy::MAX_INPUT_BYTES;
use axum::body::Body;
use axum::extract::{Extension, Request, State};
use axum::http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use dissect3d_api::ErrorCode;
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new().route("/v1/inputs", post(capture))
}

async fn capture(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    #[cfg(test)]
    state.test_hooks.upload().await;
    if request
        .extensions()
        .get::<super::framing::WireFraming>()
        .is_some_and(|framing| framing.duplicate_length())
    {
        return super::access::error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            false,
        );
    }
    let (length, media_type) = match upload_headers(request.headers()) {
        Ok(value) => value,
        Err((status, code)) => return super::access::error_response(status, code, false),
    };
    match state
        .inputs
        .capture(
            authorized.context,
            length,
            media_type,
            request.into_body().into_data_stream(),
        )
        .await
    {
        Ok(receipt) => (StatusCode::CREATED, Json(receipt)).into_response(),
        Err(error) => input_error(error),
    }
}

fn input_error(error: InputError) -> Response {
    match error {
        InputError::Transfer => {
            super::access::error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false)
        }
        InputError::Storage => super::access::error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageUnavailable,
            true,
        ),
        InputError::Capacity(limit) => super::access::capacity_response(limit),
        InputError::Store(error) => store_error(error),
    }
}

fn upload_headers(headers: &HeaderMap) -> Result<(u64, String), (StatusCode, ErrorCode)> {
    let lengths = headers.get_all(CONTENT_LENGTH);
    if headers.get_all(TRANSFER_ENCODING).iter().next().is_some()
        || headers.get_all(CONTENT_ENCODING).iter().next().is_some()
    {
        return Err((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest));
    }
    if lengths.iter().count() == 0 {
        return Err((StatusCode::LENGTH_REQUIRED, ErrorCode::LengthRequired));
    }
    if lengths.iter().count() != 1 {
        return Err((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest));
    }
    let raw_length = lengths
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest))?;
    if raw_length.is_empty() || !raw_length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest));
    }
    let declared_length = raw_length
        .parse::<u64>()
        .map_err(|_| (StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest))?;
    if declared_length == 0 {
        return Err((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest));
    }
    if declared_length > MAX_INPUT_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, ErrorCode::PayloadTooLarge));
    }
    let types = headers.get_all(CONTENT_TYPE);
    if types.iter().count() != 1 {
        return Err((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest));
    }
    let media_type = types
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest))?;
    if !media_type.eq_ignore_ascii_case("application/octet-stream") {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::UnsupportedMediaType,
        ));
    }
    Ok((declared_length, media_type.to_ascii_lowercase()))
}

fn store_error(error: crate::CoreError) -> Response {
    if let crate::CoreError::CapacityExceeded(limit) = error {
        return super::access::capacity_response(limit);
    }
    let (status, code, retryable) = match error {
        crate::CoreError::Unauthorized => {
            (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false)
        }
        crate::CoreError::NotFound => (StatusCode::NOT_FOUND, ErrorCode::InputUnavailable, false),
        crate::CoreError::CapacityExceeded(_) | crate::CoreError::LimitReached => (
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::CapacityExceeded,
            true,
        ),
        crate::CoreError::Busy => (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true),
        crate::CoreError::StoreIncompatible | crate::CoreError::Conflict => {
            (StatusCode::CONFLICT, ErrorCode::StoreIncompatible, false)
        }
        crate::CoreError::Platform(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageUnavailable,
            true,
        ),
        crate::CoreError::StoreUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StoreUnavailable,
            true,
        ),
        crate::CoreError::InvalidStore => (
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::StorageIntegrityFault,
            false,
        ),
    };
    super::access::error_response(status, code, retryable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn measured_low_space_reports_retryable_capacity_with_the_advertised_limit() {
        let response = input_error(InputError::Store(crate::CoreError::CapacityExceeded(
            "storage_free_reserve_bytes",
        )));
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let error: dissect3d_api::ApiError = dissect3d_api::decode_json(&bytes).unwrap();
        assert_eq!(error.error.code, ErrorCode::CapacityExceeded);
        assert!(error.error.retryable);
        assert_eq!(
            error.error.details,
            Some(serde_json::json!({"limit": "storage_free_reserve_bytes"}))
        );
    }

    #[test]
    fn canonicalizes_bare_media_type_without_accepting_parameters_or_duplicates() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, "1".parse().unwrap());
        headers.insert(CONTENT_TYPE, "Application/Octet-Stream".parse().unwrap());
        assert_eq!(
            upload_headers(&headers).unwrap(),
            (1, "application/octet-stream".to_owned())
        );
        headers.insert(
            CONTENT_TYPE,
            "application/octet-stream; charset=utf-8".parse().unwrap(),
        );
        assert!(upload_headers(&headers).is_err());
        headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
        headers.append(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
        assert!(upload_headers(&headers).is_err());
    }

    #[tokio::test]
    async fn storage_failure_is_distinct_from_malformed_transfer() {
        for (failure, status, code) in [
            (
                InputError::Storage,
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StorageUnavailable,
            ),
            (
                InputError::Transfer,
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidRequest,
            ),
            (
                InputError::Store(crate::CoreError::StoreUnavailable),
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::StoreUnavailable,
            ),
        ] {
            let response = input_error(failure);
            assert_eq!(response.status(), status);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let error: dissect3d_api::ApiError = dissect3d_api::decode_json(&bytes).unwrap();
            assert_eq!(error.error.code, code);
        }
    }
}
