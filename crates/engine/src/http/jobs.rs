//! HTTP adaptation for engine-owned submission and private job inspection.

use super::{AuthorizedRequest, ServiceState};
use crate::submission::SubmissionError;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Extension, Path, Request, State},
    http::{
        StatusCode,
        header::{CONTENT_ENCODING, CONTENT_TYPE, TRANSFER_ENCODING},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dissect3d_api::{ErrorCode, IdempotencyKey, JobId, JobsQuery, decode_job_request};
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new()
        .route("/v1/jobs", post(submit).get(list))
        .route("/v1/jobs/{job_id}", get(show))
}

async fn submit(
    State(state): State<Arc<ServiceState>>,
    Extension(auth): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    #[cfg(test)]
    {
        state
            .test_hooks
            .submit_seen
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if state
            .test_hooks
            .drop_before
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return lost_response();
        }
    }
    let headers = request.headers();
    if request.uri().query().is_some()
        || headers.get_all(TRANSFER_ENCODING).iter().next().is_some()
        || headers.get_all(CONTENT_ENCODING).iter().next().is_some()
        || headers.get_all(CONTENT_TYPE).iter().count() != 1
        || request
            .extensions()
            .get::<super::framing::WireFraming>()
            .is_some_and(|value| value.duplicate_length())
    {
        return error(ErrorCode::InvalidRequest.into());
    }
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
    {
        return error(ErrorCode::UnsupportedMediaType.into());
    }
    let keys = headers.get_all("Idempotency-Key");
    let key = if keys.iter().count() == 1 {
        keys.iter()
            .next()
            .and_then(|key| key.to_str().ok())
            .and_then(|key| IdempotencyKey::parse(key).ok())
    } else {
        None
    };
    let Some(key) = key else {
        return error(ErrorCode::InvalidRequest.into());
    };
    let bytes = match tokio::time::timeout(
        super::BODY_TIMEOUT,
        to_bytes(request.into_body(), 65_536),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return error(ErrorCode::PayloadTooLarge.into()),
        Err(_) => return error(ErrorCode::InvalidRequest.into()),
    };
    let request = match decode_job_request(&bytes) {
        Ok(request) => request,
        Err(_) => return error(ErrorCode::InvalidRequest.into()),
    };
    match state.submissions.submit(auth.context, key, request).await {
        #[cfg(test)]
        Ok(_)
            if state
                .test_hooks
                .drop_after
                .swap(false, std::sync::atomic::Ordering::AcqRel) =>
        {
            lost_response()
        }
        Ok(receipt) => (
            if receipt.replayed {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(receipt),
        )
            .into_response(),
        Err(problem) => error(problem),
    }
}

#[cfg(test)]
fn lost_response() -> Response {
    let stream = futures_util::stream::once(async {
        Err::<Vec<u8>, _>(std::io::Error::other("private test transport loss"))
    });
    Response::new(Body::from_stream(stream))
}

async fn show(
    State(state): State<Arc<ServiceState>>,
    Extension(auth): Extension<AuthorizedRequest>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    if request.uri().query().is_some() {
        return error(ErrorCode::InvalidRequest.into());
    }
    let id = match JobId::parse(id) {
        Ok(id) => id,
        Err(_) => return error(ErrorCode::NotFound.into()),
    };
    match state.jobs.show(auth.context, id).await {
        Ok(job) => Json(job).into_response(),
        Err(problem) => error(problem),
    }
}

async fn list(
    State(state): State<Arc<ServiceState>>,
    Extension(auth): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    let query =
        match super::discovery::query_params(request.uri().query(), &["limit", "cursor"], 4096)
            .and_then(|params| super::discovery::page_query(&params))
        {
            Ok(page) => JobsQuery {
                limit: page.limit,
                cursor: page.cursor,
            },
            Err(_) => return error(ErrorCode::InvalidRequest.into()),
        };
    match state.jobs.list(auth.context, query).await {
        Ok(page) => Json(page).into_response(),
        Err(problem) => error(problem),
    }
}

pub(super) fn error(problem: SubmissionError) -> Response {
    if let Some(limit) = problem.limit {
        return super::access::capacity_response(limit);
    }
    let (status, retryable) = match problem.code {
        ErrorCode::Unauthorized => (StatusCode::UNAUTHORIZED, false),
        ErrorCode::Forbidden => (StatusCode::FORBIDDEN, false),
        ErrorCode::NotFound | ErrorCode::InputUnavailable => (StatusCode::NOT_FOUND, false),
        ErrorCode::IdempotencyConflict
        | ErrorCode::NotPrepared
        | ErrorCode::IncompatibleProfile
        | ErrorCode::IncompatibleContract
        | ErrorCode::JobCursorExpired => (StatusCode::CONFLICT, false),
        ErrorCode::InvalidInput
        | ErrorCode::UnsupportedParameter
        | ErrorCode::RequiredFeatureUnsupported
        | ErrorCode::AmbiguousSelection => (StatusCode::UNPROCESSABLE_ENTITY, false),
        ErrorCode::CapacityExceeded => (StatusCode::TOO_MANY_REQUESTS, true),
        ErrorCode::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, false),
        ErrorCode::UnsupportedMediaType => (StatusCode::UNSUPPORTED_MEDIA_TYPE, false),
        ErrorCode::Busy
        | ErrorCode::EngineStopping
        | ErrorCode::EngineRecovering
        | ErrorCode::StoreUnavailable
        | ErrorCode::StorageUnavailable
        | ErrorCode::StorageIntegrityFault => (StatusCode::SERVICE_UNAVAILABLE, true),
        _ => (StatusCode::BAD_REQUEST, false),
    };
    super::access::error_response(status, problem.code, retryable)
}

#[cfg(test)]
mod tests {
    #[test]
    fn jobs_paging_rejects_signed_or_noncanonical_limits() {
        for value in ["+1", "-1", "01", " 1", "1.0"] {
            let params = [("limit".to_owned(), value.to_owned())].into();
            assert!(
                super::super::discovery::page_query(&params).is_err(),
                "{value}"
            );
        }
    }
}
