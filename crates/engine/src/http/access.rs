//! The one access gate shared by every registered HTTP route and fallback.
//!
//! Hyper applies parser limits before this middleware runs. This layer checks
//! Host and Origin, validates the bearer, and asks the metadata actor for one
//! serialized authorization/identity snapshot before any body is decoded.

#[cfg(unix)]
use super::UploadDeadlineSignal;
use super::{AuthorizedRequest, BODY_TIMEOUT, MAX_BODY_BYTES, ServiceState, engine_info};
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, Path, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, Method, StatusCode, Version};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use dissect3d_api::{
    ApiError, ApiErrorBody, AuthRevokeRequest, AuthStatus, ClientId, CorrelationId, EngineInfo,
    ErrorCode, IdempotencyKey, OperationId, OperationReceipt, OperationTarget, ShutdownRequest,
    TokenDigest, decode_json,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

pub(super) fn router(state: Arc<ServiceState>) -> Router {
    let router = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/auth/status", get(status))
        .route("/v1/auth/revoke", post(revoke))
        .route("/v1/operations", post(operation_create))
        .route("/v1/operations/{operation_id}", get(operation))
        .merge(super::discovery::routes());
    #[cfg(unix)]
    let router = router
        .merge(super::inputs::routes())
        .merge(super::jobs::routes());
    router
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            limit_response,
        ))
        .with_state(state)
}

async fn limit_response(
    State(state): State<Arc<ServiceState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let commit_capable = request.method() == Method::POST && request.uri().path() == "/v1/jobs";
    let method = match *request.method() {
        Method::GET => "get",
        Method::POST => "post",
        _ => "other",
    };
    let route = match request.uri().path() {
        "/v1/info" => "info",
        "/v1/auth/status" => "auth_status",
        "/v1/auth/revoke" => "auth_revoke",
        "/v1/operations" => "operation_create",
        path if path.starts_with("/v1/operations/") => "operation_read",
        "/v1/inputs" => "input_create",
        "/v1/models" => "models_list",
        path if path.starts_with("/v1/models/") => "models_show",
        "/v1/runtimes" => "runtimes_list",
        path if path.starts_with("/v1/runtimes/") => "runtimes_show",
        "/v1/tasks" => "tasks_list",
        path if path.starts_with("/v1/tasks/") => "tasks_show",
        _ => "other",
    };
    let response = next.run(request).await;
    let limit = state.policy.control_response_bytes;
    let (parts, body) = response.into_parts();
    match to_bytes(body, limit).await {
        Ok(body) => {
            let (correlation, error_code) = if !parts.status.is_success() {
                decode_json::<ApiError>(&body).map_or_else(
                    |_| (correlation_id(), None),
                    |error| {
                        let code = serde_json::to_value(error.error.code)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned));
                        (error.error.correlation_id, code)
                    },
                )
            } else {
                (correlation_id(), None)
            };
            if let Ok(permit) = state.diagnostic_permit.clone().try_acquire_owned() {
                let root = state.diagnostic_root.clone();
                let status = parts.status.as_u16();
                let _diagnostic_write = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    crate::diagnostics::record_http_request(
                        &root,
                        correlation,
                        method,
                        route,
                        status,
                        error_code,
                    );
                });
            }
            Response::from_parts(parts, Body::from(body))
        }
        // Acceptance may already be durable. A broken receipt transport cannot
        // be replaced with a rejection that tells the client no job exists.
        Err(error) if commit_capable => Response::from_parts(
            parts,
            Body::from_stream(futures_util::stream::once(async move {
                Err::<Vec<u8>, _>(error)
            })),
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::TransferLimit,
            false,
        ),
    }
}

async fn authorize(
    State(state): State<Arc<ServiceState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    if request.version() != Version::HTTP_11 {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    if !exact_single_header(request.headers(), HOST, state.host.as_bytes()) {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::HostDenied, false);
    }
    if request.headers().get_all(ORIGIN).iter().next().is_some() {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::OriginDenied, false);
    }
    let Some((client_id, digest)) = parse_authorization(request.headers()) else {
        return error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false);
    };
    let store = state.store.clone();
    let authorized = match tokio::task::spawn_blocking(move || {
        store.authorize_snapshot(client_id, digest)
    })
    .await
    {
        Ok(Ok((identity, context))) => AuthorizedRequest { identity, context },
        Ok(Err(crate::CoreError::Busy)) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true);
        }
        Ok(Err(crate::CoreError::StoreIncompatible)) => {
            return error_response(StatusCode::CONFLICT, ErrorCode::StoreIncompatible, false);
        }
        Ok(Err(crate::CoreError::Unauthorized)) => {
            return error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false);
        }
        Ok(Err(_)) | Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::PersistenceUnavailable,
                true,
            );
        }
    };
    if let Some(grant) = required_grant(request.method(), request.uri().path())
        && !authorized
            .context
            .granted_operations()
            .iter()
            .any(|item| item == grant)
    {
        return error_response(StatusCode::FORBIDDEN, ErrorCode::Forbidden, false);
    }
    request.extensions_mut().insert(authorized);
    #[cfg(unix)]
    let is_upload = request.method() == Method::POST && request.uri().path() == "/v1/inputs";
    #[cfg(unix)]
    let request_timeout = if is_upload {
        // Capture owns its single 600-second deadline, including finalization.
        // Failure cleanup may use two seconds of slack; receipt-producing work
        // never gets a second finalization budget.
        crate::inputs::policy::UPLOAD_REQUEST_TIMEOUT
    } else {
        Duration::from_millis(u64::from(state.policy.request_timeout_ms))
    };
    #[cfg(not(unix))]
    let request_timeout = Duration::from_millis(u64::from(state.policy.request_timeout_ms));
    #[cfg(unix)]
    if is_upload && let Some(signal) = request.extensions().get::<UploadDeadlineSignal>() {
        signal.signal();
    }
    // A commit-capable submission outlives a disconnected caller. Its outer
    // connection deadline closes the transport; never fabricate a rejection
    // while the engine-owned blocking handoff can still commit.
    if request.method() == Method::POST && request.uri().path() == "/v1/jobs" {
        return next.run(request).await;
    }
    match tokio::time::timeout(request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true),
    }
}

fn required_grant(method: &Method, path: &str) -> Option<&'static str> {
    match (method, path) {
        (&Method::GET, "/v1/info") => Some("engine.info"),
        (&Method::GET, "/v1/models" | "/v1/runtimes" | "/v1/tasks") => Some("engine.info"),
        (&Method::GET, path)
            if ["/v1/models/", "/v1/runtimes/", "/v1/tasks/"]
                .iter()
                .any(|prefix| {
                    path.strip_prefix(prefix)
                        .is_some_and(|selector| !selector.is_empty() && !selector.contains('/'))
                }) =>
        {
            Some("engine.info")
        }
        (&Method::GET, "/v1/auth/status") => Some("auth.status"),
        (&Method::POST, "/v1/auth/revoke") => Some("auth.revoke_self"),
        (&Method::POST, "/v1/operations") => Some("engine.shutdown"),
        (&Method::POST, "/v1/inputs") => Some("inputs.create"),
        (&Method::POST, "/v1/jobs") => Some("jobs.submit"),
        (&Method::GET, "/v1/jobs") => Some("jobs.list"),
        (&Method::GET, path) if path.starts_with("/v1/jobs/") => Some("jobs.show"),
        (&Method::GET, path)
            if path
                .strip_prefix("/v1/operations/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/')) =>
        {
            Some("operation.show_own")
        }
        _ => None,
    }
}

fn exact_single_header(headers: &HeaderMap, name: axum::http::HeaderName, expected: &[u8]) -> bool {
    let values = headers.get_all(name);
    values.iter().count() == 1
        && values
            .iter()
            .next()
            .is_some_and(|value| value.as_bytes() == expected)
}

fn parse_authorization(headers: &HeaderMap) -> Option<(ClientId, TokenDigest)> {
    let values = headers.get_all(AUTHORIZATION);
    if values.iter().count() != 1 {
        return None;
    }
    let value = values.iter().next()?.to_str().ok()?;
    let bearer = value.strip_prefix("Bearer ")?;
    let (client, secret) = bearer.split_once('.')?;
    let client_id = ClientId::parse(client.to_owned()).ok()?;
    if secret.len() != 64
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut secret_bytes = [0_u8; 32];
    for (index, pair) in secret.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        secret_bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    let digest = Sha256::digest(secret_bytes);
    secret_bytes.fill(0);
    let mut digest_bytes = [0_u8; 32];
    digest_bytes.copy_from_slice(&digest);
    Some((client_id, TokenDigest::new(digest_bytes)))
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("bearer alphabet was validated before conversion"),
    }
}

async fn info(
    Extension(authorized): Extension<AuthorizedRequest>,
    State(state): State<Arc<ServiceState>>,
) -> Json<EngineInfo> {
    #[cfg(all(unix, test))]
    state.test_hooks.info().await;
    let info = engine_info(
        authorized.identity,
        authorized.context,
        &state.policy,
        state.store.is_stopping(),
    )
    .await;
    #[cfg(unix)]
    let info = {
        let mut info = info;
        {
            let capability = crate::submission::service::capability();
            info.supported_operations.extend(
                ["jobs.submit", "jobs.list", "jobs.show"]
                    .into_iter()
                    .map(str::to_owned),
            );
            info.submission = Some(capability);
        }
        info
    };
    Json(info)
}

async fn status(Extension(authorized): Extension<AuthorizedRequest>) -> Json<AuthStatus> {
    let granted_operations = authorized.context.granted_operations().to_vec();
    Json(AuthStatus {
        api_version: "1.0".to_owned(),
        installation_id: authorized.identity.installation_id,
        instance_id: authorized.identity.instance_id,
        client_id: authorized.context.client_id().clone(),
        active: true,
        granted_operations,
    })
}

async fn operation(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    Path(raw_id): Path<String>,
) -> Response {
    let operation_id = match OperationId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false),
    };
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || {
        store.show_operation(authorized.context, operation_id)
    })
    .await
    {
        Ok(Ok(snapshot)) => Json(snapshot).into_response(),
        Ok(Err(crate::CoreError::Unauthorized)) => {
            error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false)
        }
        Ok(Err(crate::CoreError::NotFound)) => {
            error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, false)
        }
        Ok(Err(crate::CoreError::Busy)) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true)
        }
        Ok(Err(_)) | Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::PersistenceUnavailable,
            true,
        ),
    }
}

async fn revoke(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    if !exact_single_header(request.headers(), CONTENT_TYPE, b"application/json") {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::InvalidRequest,
            false,
        );
    }
    let body =
        match tokio::time::timeout(BODY_TIMEOUT, to_bytes(request.into_body(), MAX_BODY_BYTES))
            .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorCode::TransferLimit,
                    false,
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    ErrorCode::InvalidRequest,
                    true,
                );
            }
        };
    let body: AuthRevokeRequest = match decode_json(&body) {
        Ok(body) => body,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false),
    };
    if body.api_version != "1.0" {
        return error_response(StatusCode::CONFLICT, ErrorCode::IncompatibleContract, false);
    }
    if !body.required_features.is_empty() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RequiredFeatureUnsupported,
            false,
        );
    }
    let store = state.store.clone();
    match tokio::task::spawn_blocking(move || store.revoke_self(authorized.context)).await {
        Ok(Ok(receipt)) => Json(receipt).into_response(),
        Ok(Err(crate::CoreError::Unauthorized)) => {
            error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false)
        }
        Ok(Err(crate::CoreError::Busy)) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true)
        }
        Ok(Err(_)) | Err(_) => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::PersistenceUnavailable,
            true,
        ),
    }
}

async fn operation_create(
    State(state): State<Arc<ServiceState>>,
    Extension(authorized): Extension<AuthorizedRequest>,
    request: Request<Body>,
) -> Response {
    let keys = request.headers().get_all("Idempotency-Key");
    if keys.iter().count() != 1 {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    }
    let Some(key) = keys
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| IdempotencyKey::parse(value.to_owned()).ok())
    else {
        return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false);
    };
    if !exact_single_header(request.headers(), CONTENT_TYPE, b"application/json") {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ErrorCode::InvalidRequest,
            false,
        );
    }
    let body =
        match tokio::time::timeout(BODY_TIMEOUT, to_bytes(request.into_body(), MAX_BODY_BYTES))
            .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorCode::TransferLimit,
                    false,
                );
            }
            Err(_) => {
                return error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    ErrorCode::InvalidRequest,
                    true,
                );
            }
        };
    let body: ShutdownRequest = match decode_json(&body) {
        Ok(body) => body,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, false),
    };
    if body.api_version != "1.0" {
        return error_response(StatusCode::CONFLICT, ErrorCode::IncompatibleContract, false);
    }
    if !body.required_features.is_empty() {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            ErrorCode::RequiredFeatureUnsupported,
            false,
        );
    }
    if body.kind != "engine.shutdown" || body.target.kind != "engine" {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::OperationUnavailable,
            false,
        );
    }
    let store = state.store.clone();
    let receipt = match tokio::task::spawn_blocking(move || {
        store.request_shutdown(authorized.context, body.target.instance_id, key)
    })
    .await
    {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(crate::CoreError::Unauthorized)) => {
            return error_response(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, false);
        }
        Ok(Err(crate::CoreError::Conflict)) => {
            return error_response(StatusCode::CONFLICT, ErrorCode::IdempotencyConflict, false);
        }
        Ok(Err(crate::CoreError::LimitReached)) => {
            return error_response(StatusCode::TOO_MANY_REQUESTS, ErrorCode::Busy, true);
        }
        Ok(Err(crate::CoreError::Busy)) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Busy, true);
        }
        Ok(Err(_)) | Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::PersistenceUnavailable,
                true,
            );
        }
    };
    let status = if receipt.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    (
        status,
        Json(OperationReceipt {
            api_version: receipt.api_version,
            accepted: true,
            operation_id: receipt.operation_id,
            target: OperationTarget {
                kind: "engine".to_owned(),
                instance_id: receipt.instance_id,
            },
            state: receipt.state,
            replayed: receipt.replayed,
        }),
    )
        .into_response()
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, ErrorCode::NotFound, false)
}

async fn method_not_allowed() -> Response {
    error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        ErrorCode::InvalidRequest,
        false,
    )
}

pub(super) fn error_response(status: StatusCode, code: ErrorCode, retryable: bool) -> Response {
    let correlation_id = correlation_id();
    let error = ApiError {
        api_version: "1.0".to_owned(),
        error: ApiErrorBody {
            code,
            message: error_message(code).to_owned(),
            correlation_id,
            retryable,
            details: None,
        },
        operation_id: None,
    };
    (status, Json(error)).into_response()
}

#[cfg(unix)]
pub(super) fn capacity_response(limit: &'static str) -> Response {
    let mut response = ApiError {
        api_version: "1.0".to_owned(),
        error: ApiErrorBody {
            code: ErrorCode::CapacityExceeded,
            message: error_message(ErrorCode::CapacityExceeded).to_owned(),
            correlation_id: correlation_id(),
            retryable: true,
            details: Some(serde_json::json!({"limit": limit})),
        },
        operation_id: None,
    };
    // Only fixed policy keys may enter diagnostics/public details.
    if !matches!(
        limit,
        "upload_concurrency_max"
            | "staged_input_records_max"
            | "staging_reserved_bytes_max"
            | "queued_jobs_max"
            | "submission_bindings_max"
            | "captured_input_bytes_max"
            | "job_metadata_bytes_max"
            | "storage_free_reserve_bytes"
    ) {
        response.error.details = None;
    }
    (StatusCode::TOO_MANY_REQUESTS, Json(response)).into_response()
}

pub(super) fn discovery_error_response(
    status: StatusCode,
    code: ErrorCode,
    details: Option<serde_json::Value>,
) -> Response {
    let error = ApiError {
        api_version: "1.0".to_owned(),
        error: ApiErrorBody {
            code,
            message: error_message(code).to_owned(),
            correlation_id: correlation_id(),
            retryable: false,
            details,
        },
        operation_id: None,
    };
    (status, Json(error)).into_response()
}

fn error_message(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::Unauthorized => "Credential is missing, invalid or revoked",
        ErrorCode::Forbidden => "Credential is not authorized for this operation",
        ErrorCode::OriginDenied => "Browser-origin requests are not accepted",
        ErrorCode::HostDenied => "Request Host does not match this engine endpoint",
        ErrorCode::InvalidRequest => "Request is malformed or unsupported",
        ErrorCode::IdempotencyConflict => "Idempotency key conflicts with prior content",
        ErrorCode::StoreIncompatible => "Engine metadata is incompatible",
        ErrorCode::TransferLimit => "Request or response exceeded a configured limit",
        ErrorCode::EngineRecovering => "Engine is recovering",
        ErrorCode::PersistenceUnavailable => "Engine persistence is unavailable",
        ErrorCode::StorageUnavailable => "Engine storage is unavailable",
        ErrorCode::RequiredFeatureUnsupported => "A required feature is unsupported",
        ErrorCode::IncompatibleContract => "API contract version is incompatible",
        ErrorCode::OperationUnavailable => "Operation is unavailable in this engine version",
        ErrorCode::NotFound => "Route was not found",
        ErrorCode::AmbiguousSelection => "Selection is ambiguous",
        ErrorCode::InventoryCursorExpired => "Inventory cursor expired",
        ErrorCode::Busy => "Engine is busy; retry the read later",
        ErrorCode::InputUnavailable => "Input is unavailable",
        ErrorCode::NotPrepared => "Selected support is not prepared",
        ErrorCode::IncompatibleProfile => "Selected runtime profile is incompatible",
        ErrorCode::JobCursorExpired => "Job cursor expired",
        ErrorCode::DataDeleted => "Previously accepted data is unavailable",
        ErrorCode::LengthRequired => "A valid Content-Length is required",
        ErrorCode::PayloadTooLarge => "Request payload exceeded a configured limit",
        ErrorCode::UnsupportedMediaType => "Input media type is unsupported",
        ErrorCode::InvalidInput => "Input content is invalid",
        ErrorCode::UnsupportedParameter => "A requested parameter is unsupported",
        ErrorCode::CapacityExceeded => "Engine submission capacity is exhausted",
        ErrorCode::EngineStopping => "Engine is stopping",
        ErrorCode::StoreUnavailable => "Engine metadata store is unavailable",
        ErrorCode::StorageIntegrityFault => "Stored input integrity could not be verified",
    }
}

fn correlation_id() -> CorrelationId {
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_ok() {
        let mut encoded = String::with_capacity(37);
        encoded.push_str("corr_");
        for byte in random {
            encoded.push(hex_digit(byte >> 4) as char);
            encoded.push(hex_digit(byte & 15) as char);
        }
        if let Ok(value) = CorrelationId::parse(encoded) {
            return value;
        }
    }
    CorrelationId::parse("corr_00000000000000000000000000000000")
        .expect("fixed correlation identifier is valid")
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

#[cfg(test)]
mod response_limit_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Response;

    #[tokio::test]
    async fn control_response_limit_rejects_instead_of_truncating() {
        let response = Response::new(Body::from("four"));
        assert!(to_bytes(response.into_body(), 3).await.is_err());
        let response = Response::new(Body::from("four"));
        assert_eq!(
            to_bytes(response.into_body(), 4).await.expect("body"),
            "four"
        );
    }

    #[tokio::test]
    async fn auth_status_reports_the_authenticated_clients_full_grant_set() {
        let grants = [
            "auth.revoke_self",
            "auth.status",
            "engine.info",
            "engine.shutdown",
            "inputs.create",
            "jobs.list",
            "jobs.show",
            "jobs.submit",
            "operation.show_own",
        ]
        .map(str::to_owned)
        .to_vec();
        let authorized = AuthorizedRequest {
            identity: super::super::StoreIdentity {
                installation_id: dissect3d_api::InstallationId::parse(
                    "ins_0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                instance_id: dissect3d_api::InstanceId::parse(
                    "eng_0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            },
            context: crate::AuthContext {
                installation_id: dissect3d_api::InstallationId::parse(
                    "ins_0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
                client_id: ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap(),
                granted_operations: grants.clone(),
            },
        };
        let actual = status(Extension(authorized)).await.0;
        assert_eq!(actual.granted_operations, grants);
    }
}
