//! Bounded HTTPS client for one discovered engine instance.
//!
//! The client is built from protected discovery material. Its dedicated TLS
//! roots, numeric loopback URL checks, disabled proxy/redirect/retry behavior,
//! and bounded response reads keep credentials attached only to the intended
//! local engine connection.

use crate::submission::validation::{valid_digest, valid_media_type, valid_public_id};
use crate::{
    AcceptanceReceipt, ApiError, AuthRevokeRequest, AuthStatus, ClientId, DiscoveryCapability,
    EngineInfo, ErrorCode, IdempotencyKey, InputReceipt, InstallationId, InstanceId,
    InventoryDetail, InventoryPage, JobId, JobPage, JobRequest, JobSnapshot, JobsQuery,
    ModelDetail, ModelListQuery, ModelLookup, ModelSummary, OperationId, OperationReceipt,
    OperationSnapshot, OperationTarget, PageQuery, RevocationReceipt, RuntimeDetail, RuntimeLookup,
    RuntimeSummary, SecretToken, ShutdownOptions, ShutdownRequest, SubmissionCapability,
    TaskDetail, TaskKey, TaskListQuery, TaskLookup, TaskSummary, decode_json,
    decode_submission_json, encode_job_request,
};
use reqwest::Body;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

mod execution;
#[cfg(test)]
mod execution_tests;

mod core_service;
mod discovery;
mod results;
mod submission;
#[cfg(test)]
use discovery::*;
pub use results::{ArtifactStream, VerifiedManifest};
use submission::*;

const API_VERSION: &str = "1.0";
const MAX_CLIENT_RESPONSE_BYTES: usize = 262_144;
const MAX_SUBMISSION_REQUEST_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: u64 = 268_435_456;
const INPUT_STREAM_CHUNK_BYTES: usize = 65_536;
const INPUT_STREAM_CHANNEL_CHUNKS: usize = 2;
const INPUT_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const INPUT_UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
const SAFE_READ_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Default engine connect timeout in milliseconds (`CT-CLI-SURFACE` §2
/// `connect_timeout_ms`, range 100..30,000). Clients without their own
/// preference resolution use it through [`ClientLimits::default`].
pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1_000;
/// Default per-request read timeout in milliseconds (`CT-CLI-SURFACE` §2
/// `read_timeout_ms`, range 100..60,000).
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 5_000;

/// Trust and identity material obtained from protected engine discovery.
pub struct ConnectionMaterial {
    base_url: String,
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    trust_anchor_der: Vec<u8>,
    trust_anchor_sha256: [u8; 32],
    credential: SecretToken,
}

impl ConnectionMaterial {
    pub fn new(
        base_url: String,
        installation_id: InstallationId,
        instance_id: InstanceId,
        client_id: ClientId,
        trust_anchor_der: Vec<u8>,
        trust_anchor_sha256: [u8; 32],
        credential: SecretToken,
    ) -> Self {
        Self {
            base_url,
            installation_id,
            instance_id,
            client_id,
            trust_anchor_der,
            trust_anchor_sha256,
            credential,
        }
    }
}

/// Finite network limits shared by the API client methods.
#[derive(Clone, Copy, Debug)]
pub struct ClientLimits {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub read_attempts: u8,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS),
            request_timeout: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS),
            max_response_bytes: MAX_CLIENT_RESPONSE_BYTES,
            read_attempts: 1,
        }
    }
}

/// Safe client failure categories; transport and response bodies stay private.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("invalid connection material")]
    InvalidMaterial,
    #[error("engine connection failed")]
    Transport,
    #[error("engine rejected the request")]
    Rejected(ErrorCode),
    #[error("engine identity or contract changed")]
    Incompatible,
    #[error("engine returned an invalid response")]
    InvalidResponse,
    #[error("engine response exceeded the configured limit")]
    TransferLimit,
}

/// Submission-call outcome. A post-send transport or decode failure is kept
/// distinct because the engine may already have committed the request.
#[derive(Clone, Debug, Error)]
pub enum SubmissionClientError {
    #[error("submission could not be sent")]
    BeforeSend(ClientError),
    #[error("caller interrupted before the submission POST")]
    CancelledBeforeSend,
    #[error("engine definitively rejected the submission")]
    Rejected(Box<ApiError>),
    #[error("submission may have reached the engine")]
    Uncertain {
        correlation_id: Option<crate::CorrelationId>,
    },
}

/// Shared typed client. It owns no profile discovery or filesystem behavior.
pub struct Client {
    http: reqwest::Client,
    upload_http: reqwest::Client,
    base_url: String,
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    credential: SecretToken,
    limits: ClientLimits,
}

impl Client {
    /// Create an HTTPS-only client rooted in one validated installation CA.
    pub fn new(material: ConnectionMaterial, limits: ClientLimits) -> Result<Self, ClientError> {
        if !valid_loopback_url(&material.base_url)
            || material.trust_anchor_der.is_empty()
            || material.trust_anchor_der.len() > crate::MAX_TRUST_ANCHOR_DER_BYTES
            || limits.connect_timeout.is_zero()
            || limits.request_timeout.is_zero()
            || limits.max_response_bytes == 0
            || limits.max_response_bytes > MAX_CLIENT_RESPONSE_BYTES
            || !(1..=3).contains(&limits.read_attempts)
        {
            return Err(ClientError::InvalidMaterial);
        }
        let pin: [u8; 32] = Sha256::digest(&material.trust_anchor_der).into();
        if pin != material.trust_anchor_sha256 {
            return Err(ClientError::InvalidMaterial);
        }
        let certificate = reqwest::Certificate::from_der(&material.trust_anchor_der)
            .map_err(|_| ClientError::InvalidMaterial)?;
        let upload_certificate = reqwest::Certificate::from_der(&material.trust_anchor_der)
            .map_err(|_| ClientError::InvalidMaterial)?;
        let http = reqwest::Client::builder()
            .https_only(true)
            .tls_backend_rustls()
            .tls_certs_only([certificate])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .http1_max_headers(32)
            .referer(false)
            .connect_timeout(limits.connect_timeout)
            .read_timeout(limits.request_timeout)
            .timeout(limits.request_timeout)
            .build()
            .map_err(|_| ClientError::InvalidMaterial)?;
        let upload_http = reqwest::Client::builder()
            .https_only(true)
            .tls_backend_rustls()
            .tls_certs_only([upload_certificate])
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .http1_max_headers(32)
            .referer(false)
            .connect_timeout(limits.connect_timeout)
            // Reqwest starts read_timeout before response headers, including
            // upload time. Source and server enforce progress idle deadlines;
            // the request timeout bounds upload plus response independently.
            .timeout(INPUT_UPLOAD_TOTAL_TIMEOUT)
            .build()
            .map_err(|_| ClientError::InvalidMaterial)?;
        Ok(Self {
            http,
            upload_http,
            base_url: material.base_url.trim_end_matches('/').to_owned(),
            installation_id: material.installation_id,
            instance_id: material.instance_id,
            client_id: material.client_id,
            credential: material.credential,
            limits,
        })
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        retry_safe_read(
            self.limits.read_attempts,
            self.limits.request_timeout,
            || async {
                let request = self
                    .http
                    .get(format!("{}{}", self.base_url, path))
                    .header(AUTHORIZATION, self.authorization()?);
                let response = request.send().await.map_err(|_| ClientError::Transport)?;
                self.decode_response(response).await
            },
        )
        .await
    }

    async fn decode_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ClientError> {
        let status = response.status();
        let body = read_bounded(response, self.limits.max_response_bytes).await?;
        if !status.is_success() {
            let error: ApiError = decode_json(&body).map_err(|_| ClientError::InvalidResponse)?;
            if error.api_version != API_VERSION {
                return Err(ClientError::Incompatible);
            }
            return Err(ClientError::Rejected(error.error.code));
        }
        decode_json(&body).map_err(|_| ClientError::InvalidResponse)
    }

    fn authorization(&self) -> Result<HeaderValue, ClientError> {
        let mut encoded = Vec::with_capacity(
            7 + self.client_id.as_str().len() + 1 + self.credential.expose().len() * 2,
        );
        encoded.extend_from_slice(b"Bearer ");
        encoded.extend_from_slice(self.client_id.as_str().as_bytes());
        encoded.push(b'.');
        for byte in self.credential.expose() {
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
        let mut header =
            HeaderValue::from_bytes(&encoded).map_err(|_| ClientError::InvalidMaterial)?;
        header.set_sensitive(true);
        encoded.fill(0);
        Ok(header)
    }
}

fn push_query(path: &mut String, first: &mut bool, key: &str, value: &str) {
    path.push(if *first { '?' } else { '&' });
    *first = false;
    path.push_str(key);
    path.push('=');
    path.push_str(&encode_component(value));
}

fn encode_component(value: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(char::from(byte));
        } else {
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

async fn retry_safe_read<T, F, Fut>(
    attempts: u8,
    total_timeout: Duration,
    mut action: F,
) -> Result<T, ClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ClientError>>,
{
    let deadline = tokio::time::Instant::now() + total_timeout;
    for attempt in 0..attempts {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::Transport);
        }
        let retryable = match tokio::time::timeout(remaining, action()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(ClientError::Transport)) | Err(_) if attempt + 1 < attempts => true,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(ClientError::Transport),
        };
        if retryable {
            let delay = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(SAFE_READ_RETRY_DELAY);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(ClientError::Transport)
}

async fn read_bounded(
    mut response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, ClientError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or(ClientError::TransferLimit)?;
        if next > maximum {
            return Err(ClientError::TransferLimit);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn valid_loopback_url(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some_and(|port| port != 0)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + (value - 10),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientError, INPUT_CAPTURE_LIMITS, REQUIRED_SUBMISSION_LIMITS, SUBMISSION_OPERATIONS,
        retry_safe_read, stream_input, validate_discovery_capability,
        validate_submission_capability,
    };
    use crate::{DiscoveryCapability, ErrorCode, SubmissionCapability};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn safe_get_retries_only_transport_failures_within_the_attempt_limit() {
        let attempts = AtomicUsize::new(0);
        let started = tokio::time::Instant::now();
        let result = retry_safe_read(2, Duration::from_secs(1), || {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(ClientError::Transport)
                } else {
                    Ok("ok")
                }
            }
        })
        .await;
        assert_eq!(result, Ok("ok"));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(started.elapsed() >= Duration::from_millis(90));

        let attempts = AtomicUsize::new(0);
        let result: Result<(), ClientError> = retry_safe_read(3, Duration::from_secs(1), || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(ClientError::Rejected(crate::ErrorCode::Unauthorized)) }
        })
        .await;
        assert_eq!(
            result,
            Err(ClientError::Rejected(crate::ErrorCode::Unauthorized))
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn optional_discovery_capability_is_checked_before_route_use() {
        let grants = vec!["engine.info".to_owned()];
        let capability = DiscoveryCapability {
            version: "1.0".to_owned(),
            operations: vec![
                "models.list",
                "models.show",
                "runtimes.list",
                "runtimes.show",
                "tasks.list",
                "tasks.show",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            authorization_grant: "engine.info".to_owned(),
        };
        assert_eq!(
            validate_discovery_capability(&grants, None, "models.list"),
            Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
        );
        assert_eq!(
            validate_discovery_capability(&[], Some(&capability), "models.list"),
            Err(ClientError::Rejected(ErrorCode::Forbidden))
        );

        let mut missing_operation = capability.clone();
        missing_operation
            .operations
            .retain(|operation| operation != "models.list");
        assert_eq!(
            validate_discovery_capability(&grants, Some(&missing_operation), "models.list"),
            Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
        );
        assert_eq!(
            validate_discovery_capability(&grants, Some(&missing_operation), "models.show"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );

        let mut wrong_version = capability.clone();
        wrong_version.version = "2.0".to_owned();
        assert_eq!(
            validate_discovery_capability(&grants, Some(&wrong_version), "models.list"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );
        let mut wrong_grant = capability.clone();
        wrong_grant.authorization_grant = "engine.execute".to_owned();
        assert_eq!(
            validate_discovery_capability(&grants, Some(&wrong_grant), "models.list"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );

        let mut reordered = capability.clone();
        reordered.operations.reverse();
        assert_eq!(
            validate_discovery_capability(&grants, Some(&reordered), "models.list"),
            Ok(())
        );
    }

    #[test]
    fn submission_capability_and_grant_are_independent_requirements() {
        let grants = SUBMISSION_OPERATIONS
            .iter()
            .map(|operation| (*operation).to_owned())
            .collect::<Vec<_>>();
        let capability = SubmissionCapability {
            version: "1.0".to_owned(),
            dispatch_enabled: false,
            operations: SUBMISSION_OPERATIONS
                .iter()
                .map(|operation| (*operation).to_owned())
                .collect(),
            limits: REQUIRED_SUBMISSION_LIMITS
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
            limits_source: "built_in".to_owned(),
        };
        assert_eq!(
            validate_submission_capability(&grants, None, "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
        );
        assert_eq!(
            validate_submission_capability(&[], None, "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
        );
        assert_eq!(
            validate_submission_capability(&[], Some(&capability), "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::Forbidden))
        );
        assert_eq!(
            validate_submission_capability(&grants, Some(&capability), "jobs.submit"),
            Ok(())
        );

        let mut wrong_version = capability.clone();
        wrong_version.version = "2.0".to_owned();
        assert_eq!(
            validate_submission_capability(&grants, Some(&wrong_version), "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );
        let mut dispatch_enabled = capability.clone();
        dispatch_enabled.dispatch_enabled = true;
        assert_eq!(
            validate_submission_capability(&grants, Some(&dispatch_enabled), "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );
        let mut missing_limit = capability.clone();
        missing_limit.limits.remove("input_bytes_max");
        assert_eq!(
            validate_submission_capability(&grants, Some(&missing_limit), "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );
        let mut wrong_grant = grants.clone();
        wrong_grant.retain(|grant| grant != "jobs.submit");
        assert_eq!(
            validate_submission_capability(&wrong_grant, Some(&capability), "jobs.submit"),
            Err(ClientError::Rejected(ErrorCode::Forbidden))
        );
    }

    #[test]
    fn capture_only_capability_does_not_claim_job_operations() {
        let capability = SubmissionCapability {
            version: "1.0".to_owned(),
            dispatch_enabled: false,
            operations: vec!["inputs.create".to_owned()],
            limits: INPUT_CAPTURE_LIMITS
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
            limits_source: "built_in".to_owned(),
        };
        assert_eq!(
            validate_submission_capability(
                &["inputs.create".to_owned()],
                Some(&capability),
                "inputs.create"
            ),
            Ok(())
        );
        assert_eq!(
            validate_submission_capability(
                &["jobs.submit".to_owned()],
                Some(&capability),
                "jobs.submit"
            ),
            Err(ClientError::Rejected(ErrorCode::OperationUnavailable))
        );
    }

    #[test]
    fn additive_capture_limits_do_not_disable_a_compatible_operation() {
        let mut capability = SubmissionCapability {
            version: "1.0".to_owned(),
            dispatch_enabled: false,
            operations: vec!["inputs.create".to_owned()],
            limits: INPUT_CAPTURE_LIMITS
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
            limits_source: "built_in".to_owned(),
        };
        capability
            .limits
            .insert("staged_input_records_max".to_owned(), 1024);
        capability
            .limits
            .insert("upload_metadata_reserve_bytes".to_owned(), 4_194_304);
        assert_eq!(
            validate_submission_capability(
                &["inputs.create".to_owned()],
                Some(&capability),
                "inputs.create"
            ),
            Ok(())
        );
        capability.limits.insert("input_bytes_max".to_owned(), 1);
        assert_eq!(
            validate_submission_capability(
                &["inputs.create".to_owned()],
                Some(&capability),
                "inputs.create"
            ),
            Err(ClientError::Rejected(ErrorCode::IncompatibleContract))
        );
    }

    #[tokio::test]
    async fn bounded_upload_producer_requires_exact_source_length() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::spawn(stream_input(
            tokio::io::BufReader::new(std::io::Cursor::new(vec![1_u8, 2, 3])),
            3,
            sender,
        ));
        let mut received = Vec::new();
        while let Some(chunk) = receiver.recv().await {
            received.extend(chunk.expect("exact source chunk"));
        }
        producer
            .await
            .expect("producer task")
            .expect("exact input length");
        assert_eq!(received, [1, 2, 3]);

        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::spawn(stream_input(
            tokio::io::BufReader::new(std::io::Cursor::new(vec![1_u8, 2, 3, 4])),
            3,
            sender,
        ));
        assert_eq!(
            receiver.recv().await.expect("content chunk").unwrap(),
            [1, 2, 3]
        );
        assert_eq!(
            receiver
                .recv()
                .await
                .expect("overrun error")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            producer.await.expect("producer task").unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );

        let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let producer = tokio::spawn(stream_input(
            tokio::io::BufReader::new(std::io::Cursor::new(vec![1_u8])),
            2,
            sender,
        ));
        assert_eq!(
            receiver.recv().await.expect("short content chunk").unwrap(),
            [1]
        );
        assert_eq!(
            receiver
                .recv()
                .await
                .expect("short source error")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            producer.await.expect("producer task").unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn safe_get_stops_after_the_configured_third_transport_failure() {
        let attempts = AtomicUsize::new(0);
        let result: Result<(), ClientError> = retry_safe_read(3, Duration::from_secs(1), || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(ClientError::Transport) }
        })
        .await;
        assert_eq!(result, Err(ClientError::Transport));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn safe_get_attempts_share_one_total_deadline() {
        let started = tokio::time::Instant::now();
        let result = retry_safe_read(3, Duration::from_millis(40), || async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, ClientError>(())
        })
        .await;
        assert_eq!(result, Err(ClientError::Transport));
        assert!(started.elapsed() < Duration::from_millis(250));
    }
}
