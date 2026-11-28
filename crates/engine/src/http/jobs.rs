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
use dissect3d_api::{
    ErrorCode, ExecutionAcceptance, ExecutionControlRequest, IdempotencyKey, JOB_CONTRACT,
    JOB_CONTRACT_HEADER, JobId, JobsQuery, decode_execution_request, decode_job_request,
};
use std::sync::Arc;

pub(super) fn routes() -> Router<Arc<ServiceState>> {
    Router::new()
        .route("/v1/jobs", post(submit).get(list))
        .route("/v1/jobs/{job_id}", get(show))
        .route("/v1/jobs/{job_id}/cancel", post(cancel))
        .route("/v1/jobs/{job_id}/retry", post(retry))
}

/// WE-001 negotiation: `Ok(true)` for exactly one `Dissect3D-Job-Contract:
/// we-0.1`, `Ok(false)` without the header, and 409 `incompatible_contract`
/// for anything else.
fn negotiated(headers: &axum::http::HeaderMap) -> Result<bool, SubmissionError> {
    let mut values = headers.get_all(JOB_CONTRACT_HEADER).iter();
    match (values.next(), values.next()) {
        (None, _) => Ok(false),
        (Some(value), None) if value.as_bytes() == JOB_CONTRACT.as_bytes() => Ok(true),
        _ => Err(ErrorCode::IncompatibleContract.into()),
    }
}

/// The execution controller, required for every negotiated request.
fn execution(
    state: &ServiceState,
) -> Result<Arc<crate::execution::controller::ExecutionHandle>, SubmissionError> {
    state
        .execution
        .clone()
        .ok_or_else(|| ErrorCode::IncompatibleContract.into())
}

/// One `Idempotency-Key` header, parsed.
fn idempotency_key(headers: &axum::http::HeaderMap) -> Option<IdempotencyKey> {
    let keys = headers.get_all("Idempotency-Key");
    if keys.iter().count() != 1 {
        return None;
    }
    keys.iter()
        .next()
        .and_then(|key| key.to_str().ok())
        .and_then(|key| IdempotencyKey::parse(key).ok())
}

/// Shared request framing: no query, no transfer/content encoding, one
/// `application/json` content type, then a bounded body.
async fn json_body(request: Request<Body>) -> Result<axum::body::Bytes, SubmissionError> {
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
        return Err(ErrorCode::InvalidRequest.into());
    }
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
    {
        return Err(ErrorCode::UnsupportedMediaType.into());
    }
    match tokio::time::timeout(super::BODY_TIMEOUT, to_bytes(request.into_body(), 65_536)).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(ErrorCode::PayloadTooLarge.into()),
        Err(_) => Err(ErrorCode::InvalidRequest.into()),
    }
}

/// The closed WE-003 control body: exactly api 1.0 and no required features.
fn control_body(bytes: &[u8]) -> Result<(), SubmissionError> {
    let body: ExecutionControlRequest = dissect3d_api::decode_submission_json(bytes, 65_536)
        .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
    if body.api_version != "1.0" {
        return Err(ErrorCode::IncompatibleContract.into());
    }
    if !body.required_features.is_empty() {
        return Err(ErrorCode::RequiredFeatureUnsupported.into());
    }
    Ok(())
}

fn acceptance(receipt: dissect3d_api::AcceptanceReceipt) -> ExecutionAcceptance {
    ExecutionAcceptance {
        api_version: receipt.api_version,
        accepted: receipt.accepted,
        job_id: receipt.job_id,
        replayed: receipt.replayed,
        acceptance_sequence: receipt.acceptance_sequence,
        snapshot_revision: receipt.snapshot_revision,
        resolved: receipt.resolved,
        job_contract: JOB_CONTRACT.to_owned(),
        retry_of: None,
    }
}

fn accepted(receipt: ExecutionAcceptance) -> Response {
    let status = if receipt.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (status, Json(receipt)).into_response()
}

/// Negotiated submission: a fresh execution request, or the exact replay of
/// an original Stage 3 body's retained binding. The controller is woken
/// after acceptance; a replay changes nothing.
async fn submit_execution(
    state: &ServiceState,
    auth: crate::AuthContext,
    key: IdempotencyKey,
    bytes: &[u8],
) -> Response {
    let handle = match execution(state) {
        Ok(handle) => handle,
        Err(problem) => return error(problem),
    };
    let result = if let Ok(request) = decode_execution_request(bytes) {
        state.submissions.submit_execution(auth, key, request).await
    } else if let Ok(request) = decode_job_request(bytes) {
        state.submissions.replay_legacy(auth, key, request).await
    } else {
        return error(ErrorCode::InvalidRequest.into());
    };
    match result {
        Ok(receipt) => {
            handle.wake();
            #[cfg(all(unix, feature = "test-support"))]
            handle.wait_pre_receipt_hold().await;
            #[cfg(test)]
            if reply_lost(state) {
                return lost_response();
            }
            accepted(acceptance(receipt))
        }
        Err(problem) => error(problem),
    }
}

async fn cancel(
    State(state): State<Arc<ServiceState>>,
    Extension(auth): Extension<AuthorizedRequest>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    match negotiated(request.headers()) {
        Ok(true) => {}
        Ok(false) => return error(ErrorCode::IncompatibleContract.into()),
        Err(problem) => return error(problem),
    }
    let handle = match execution(&state) {
        Ok(handle) => handle,
        Err(problem) => return error(problem),
    };
    let bytes = match json_body(request).await {
        Ok(bytes) => bytes,
        Err(problem) => return error(problem),
    };
    if let Err(problem) = control_body(&bytes) {
        return error(problem);
    }
    let Ok(id) = JobId::parse(id) else {
        return error(ErrorCode::NotFound.into());
    };
    match crate::execution::control::cancel(state.store.clone(), &handle, auth.context, id).await {
        #[cfg(test)]
        Ok(_) if reply_lost(&state) => lost_response(),
        Ok(response) => Json(response).into_response(),
        Err(problem) => error(problem),
    }
}

async fn retry(
    State(state): State<Arc<ServiceState>>,
    Extension(auth): Extension<AuthorizedRequest>,
    Path(id): Path<String>,
    request: Request<Body>,
) -> Response {
    match negotiated(request.headers()) {
        Ok(true) => {}
        Ok(false) => return error(ErrorCode::IncompatibleContract.into()),
        Err(problem) => return error(problem),
    }
    let handle = match execution(&state) {
        Ok(handle) => handle,
        Err(problem) => return error(problem),
    };
    let Some(key) = idempotency_key(request.headers()) else {
        return error(ErrorCode::InvalidRequest.into());
    };
    let bytes = match json_body(request).await {
        Ok(bytes) => bytes,
        Err(problem) => return error(problem),
    };
    if let Err(problem) = control_body(&bytes) {
        return error(problem);
    }
    let Ok(id) = JobId::parse(id) else {
        return error(ErrorCode::NotFound.into());
    };
    match state
        .submissions
        .retry_execution(auth.context, key, id)
        .await
    {
        Ok(receipt) => {
            handle.wake();
            #[cfg(test)]
            if reply_lost(&state) {
                return lost_response();
            }
            accepted(receipt)
        }
        Err(problem) => error(problem),
    }
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
    let negotiated = match negotiated(request.headers()) {
        Ok(negotiated) => negotiated,
        Err(problem) => return error(problem),
    };
    // An execution-enabled engine never accepts unnegotiated fresh work.
    if !negotiated && state.execution.is_some() {
        return error(ErrorCode::IncompatibleContract.into());
    }
    let key = idempotency_key(request.headers());
    let bytes = match json_body(request).await {
        Ok(bytes) => bytes,
        Err(problem) => return error(problem),
    };
    let Some(key) = key else {
        return error(ErrorCode::InvalidRequest.into());
    };
    if negotiated {
        return submit_execution(&state, auth.context, key, &bytes).await;
    }
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

/// Test hook: lose the reply of a committed mutation once.
#[cfg(test)]
fn reply_lost(state: &ServiceState) -> bool {
    state
        .test_hooks
        .drop_after
        .swap(false, std::sync::atomic::Ordering::AcqRel)
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
    let negotiated = match negotiated(request.headers()) {
        Ok(negotiated) => negotiated,
        Err(problem) => return error(problem),
    };
    let id = match JobId::parse(id) {
        Ok(id) => id,
        Err(_) => return error(ErrorCode::NotFound.into()),
    };
    if negotiated {
        let controller = match execution(&state) {
            Ok(handle) => handle,
            Err(problem) => return error(problem),
        };
        return match state
            .jobs
            .execution_show(auth.context, id, controller)
            .await
        {
            Ok(snapshot) => Json(snapshot).into_response(),
            Err(problem) => error(problem),
        };
    }
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
    let negotiated = match negotiated(request.headers()) {
        Ok(negotiated) => negotiated,
        Err(problem) => return error(problem),
    };
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
    if negotiated {
        let controller = match execution(&state) {
            Ok(handle) => handle,
            Err(problem) => return error(problem),
        };
        return match state
            .jobs
            .execution_list(auth.context, query, controller)
            .await
        {
            Ok(page) => Json(page).into_response(),
            Err(problem) => error(problem),
        };
    }
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
        | ErrorCode::JobNotTerminal
        | ErrorCode::RetryPrerequisiteUnavailable
        // Uncertain cleanup blocks conflicting work (user-confirmed 2026-11-17).
        | ErrorCode::CleanupUnconfirmed
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

    /// WE-007: uncertain cleanup blocks conflicting work, so it is a 409 conflict
    /// next to the other retry refusals (`cleanup_unconfirmed` user-confirmed 2026-11-17).
    #[test]
    fn retry_refusals_map_to_conflict() {
        use dissect3d_api::ErrorCode;
        for code in [
            ErrorCode::JobNotTerminal,
            ErrorCode::RetryPrerequisiteUnavailable,
            ErrorCode::CleanupUnconfirmed,
        ] {
            let response = super::error(code.into());
            assert_eq!(
                response.status(),
                axum::http::StatusCode::CONFLICT,
                "{code:?}"
            );
        }
    }
}
