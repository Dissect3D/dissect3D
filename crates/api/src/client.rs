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

const API_VERSION: &str = "1.0";
const MAX_CLIENT_RESPONSE_BYTES: usize = 262_144;
const MAX_SUBMISSION_REQUEST_BYTES: usize = 65_536;
const MAX_INPUT_BYTES: u64 = 268_435_456;
const INPUT_STREAM_CHUNK_BYTES: usize = 65_536;
const INPUT_STREAM_CHANNEL_CHUNKS: usize = 2;
const INPUT_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const INPUT_UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);
const SAFE_READ_RETRY_DELAY: Duration = Duration::from_millis(100);

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
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(5),
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
            || material.trust_anchor_der.len() > 65_536
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

    /// Read actual service capabilities for the discovered engine instance.
    pub async fn info(&self) -> Result<EngineInfo, ClientError> {
        let info: EngineInfo = self.get("/v1/info").await?;
        if info.api_version != API_VERSION
            || !info.required_features.is_empty()
            || info.installation_id != self.installation_id
            || info.instance_id != self.instance_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(info)
    }

    /// Read this credential's current active status and grants.
    pub async fn auth_status(&self) -> Result<AuthStatus, ClientError> {
        let status: AuthStatus = self.get("/v1/auth/status").await?;
        if status.api_version != API_VERSION
            || status.installation_id != self.installation_id
            || status.instance_id != self.instance_id
            || status.client_id != self.client_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(status)
    }

    /// Revoke only the credential attached to this client.
    pub async fn revoke_self(&self) -> Result<RevocationReceipt, ClientError> {
        let body = AuthRevokeRequest {
            api_version: API_VERSION.to_owned(),
            required_features: Vec::new(),
        };
        let response = self
            .http
            .post(format!("{}/v1/auth/revoke", self.base_url))
            .header(AUTHORIZATION, self.authorization()?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        let receipt: RevocationReceipt = self.decode_response(response).await?;
        if receipt.api_version != API_VERSION
            || receipt.client_id != self.client_id
            || !receipt.revoked
        {
            return Err(ClientError::Incompatible);
        }
        Ok(receipt)
    }

    /// Ask the discovered instance to stop under one durable idempotency key.
    pub async fn shutdown(&self, key: IdempotencyKey) -> Result<OperationReceipt, ClientError> {
        let body = ShutdownRequest {
            api_version: API_VERSION.to_owned(),
            kind: "engine.shutdown".to_owned(),
            target: OperationTarget {
                kind: "engine".to_owned(),
                instance_id: self.instance_id.clone(),
            },
            options: ShutdownOptions::default(),
            required_features: Vec::new(),
        };
        let response = self
            .http
            .post(format!("{}/v1/operations", self.base_url))
            .header(AUTHORIZATION, self.authorization()?)
            .header("Idempotency-Key", key.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        let receipt: OperationReceipt = self.decode_response(response).await?;
        if receipt.api_version != API_VERSION
            || !receipt.accepted
            || receipt.target.kind != "engine"
            || receipt.target.instance_id != self.instance_id
        {
            return Err(ClientError::Incompatible);
        }
        Ok(receipt)
    }

    /// Read one operation created by this credential.
    pub async fn operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, ClientError> {
        let snapshot: OperationSnapshot = self
            .get(&format!("/v1/operations/{}", operation_id.as_str()))
            .await?;
        if snapshot.api_version != API_VERSION
            || snapshot.operation_id != operation_id
            || snapshot.kind != "engine.shutdown"
        {
            return Err(ClientError::Incompatible);
        }
        Ok(snapshot)
    }

    /// Stream one exact-length input to the engine after capability and grant
    /// checks. The source is read through a two-chunk bounded channel.
    pub async fn create_input<R>(
        &self,
        source: R,
        length: u64,
        media_type: &str,
    ) -> Result<InputReceipt, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        let capability = self.require_submission_capability("inputs.create").await?;
        let maximum = capability
            .limits
            .get("input_bytes_max")
            .copied()
            .ok_or(ClientError::Incompatible)?
            .min(MAX_INPUT_BYTES);
        if !(1..=maximum).contains(&length) || !valid_media_type(media_type) {
            return Err(ClientError::InvalidMaterial);
        }
        let media_type = media_type.to_ascii_lowercase();

        let authorization = self.authorization()?;
        let (sender, receiver) = mpsc::channel(INPUT_STREAM_CHANNEL_CHUNKS);
        let producer = tokio::spawn(stream_input(source, length, sender));
        // A JoinHandle detaches on drop; the upload operation owns this reader.
        let _producer_lifetime = AbortOnDrop(producer.abort_handle());
        let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|chunk| (chunk, receiver))
        });
        let body = Body::wrap_stream(stream);
        let response = self
            .upload_http
            .post(format!("{}/v1/inputs", self.base_url))
            .header(AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, media_type.as_str())
            .header(reqwest::header::CONTENT_LENGTH, length)
            .timeout(INPUT_UPLOAD_TOTAL_TIMEOUT)
            .body(body)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(_) => {
                producer.abort();
                return Err(ClientError::Transport);
            }
        };
        if !response.status().is_success() {
            producer.abort();
            let decoded: Result<InputReceipt, ClientError> = self.decode_response(response).await;
            decoded?;
            return Err(ClientError::InvalidResponse);
        }
        if response.status() != reqwest::StatusCode::CREATED {
            producer.abort();
            return Err(ClientError::InvalidResponse);
        }

        match producer.await {
            Ok(Ok(())) => {}
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                ) =>
            {
                return Err(ClientError::InvalidMaterial);
            }
            Ok(Err(_)) | Err(_) => return Err(ClientError::Transport),
        }
        let receipt: InputReceipt = self.decode_response(response).await?;
        if receipt.api_version != API_VERSION
            || !receipt.complete
            || receipt.identity.byte_length != length
            || receipt.identity.media_type != media_type
            || receipt.expires_at_ms.get() <= receipt.completed_at_ms.get()
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(receipt)
    }

    /// Submit one immutable request with a single POST attempt.
    pub async fn submit_job(
        &self,
        key: &IdempotencyKey,
        request: &JobRequest,
    ) -> Result<AcceptanceReceipt, SubmissionClientError> {
        self.submit_job_observed(key, request, || true).await
    }

    /// Observe the last pre-POST boundary. Returning false sends no mutation;
    /// this never cancels a job or retries an uncertain request.
    pub async fn submit_job_observed(
        &self,
        key: &IdempotencyKey,
        request: &JobRequest,
        before_send: impl FnOnce() -> bool,
    ) -> Result<AcceptanceReceipt, SubmissionClientError> {
        let capability = self
            .require_submission_capability("jobs.submit")
            .await
            .map_err(SubmissionClientError::BeforeSend)?;
        let bytes = encode_job_request(request)
            .map_err(|_| SubmissionClientError::BeforeSend(ClientError::InvalidMaterial))?;
        if bytes.len() > MAX_SUBMISSION_REQUEST_BYTES {
            return Err(SubmissionClientError::BeforeSend(
                ClientError::TransferLimit,
            ));
        }
        if !capability
            .operations
            .iter()
            .any(|operation| operation == "jobs.submit")
        {
            return Err(SubmissionClientError::BeforeSend(ClientError::Rejected(
                ErrorCode::OperationUnavailable,
            )));
        }
        let authorization = self
            .authorization()
            .map_err(SubmissionClientError::BeforeSend)?;
        if !before_send() {
            return Err(SubmissionClientError::CancelledBeforeSend);
        }
        let send = self
            .http
            .post(format!("{}/v1/jobs", self.base_url))
            .header(AUTHORIZATION, authorization)
            .header("Idempotency-Key", key.as_str())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes)
            .send()
            .await;
        let response = match send {
            Ok(response) => response,
            Err(_) => {
                return Err(SubmissionClientError::Uncertain {
                    correlation_id: None,
                });
            }
        };
        let status = response.status();
        if !status.is_success() {
            let body = read_bounded(response, self.limits.max_response_bytes)
                .await
                .map_err(|_| SubmissionClientError::Uncertain {
                    correlation_id: None,
                })?;
            let error: ApiError =
                decode_json(&body).map_err(|_| SubmissionClientError::Uncertain {
                    correlation_id: None,
                })?;
            if error.api_version != API_VERSION {
                return Err(SubmissionClientError::Uncertain {
                    correlation_id: Some(error.error.correlation_id),
                });
            }
            return Err(SubmissionClientError::Rejected(Box::new(error)));
        }
        if status != reqwest::StatusCode::CREATED && status != reqwest::StatusCode::OK {
            return Err(SubmissionClientError::Uncertain {
                correlation_id: None,
            });
        }
        let receipt: AcceptanceReceipt = self
            .decode_submission_response(response)
            .await
            .map_err(|correlation_id| SubmissionClientError::Uncertain { correlation_id })?;
        if receipt.api_version != API_VERSION
            || !receipt.accepted
            || receipt.acceptance_sequence < 1
            || receipt.snapshot_revision != 1
            || (status == reqwest::StatusCode::CREATED && receipt.replayed)
            || (status == reqwest::StatusCode::OK && !receipt.replayed)
            || receipt.resolved.validate().is_err()
        {
            return Err(SubmissionClientError::Uncertain {
                correlation_id: None,
            });
        }
        Ok(receipt)
    }

    /// Read one bounded creator-private jobs page.
    pub async fn jobs(&self, query: JobsQuery) -> Result<JobPage, ClientError> {
        let limit = query.limit.unwrap_or(20);
        if !(1..=100).contains(&limit)
            || query
                .cursor
                .as_deref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
        {
            return Err(ClientError::InvalidMaterial);
        }
        self.require_submission_capability("jobs.list").await?;
        let mut path = String::from("/v1/jobs");
        let mut first = true;
        push_query(&mut path, &mut first, "limit", &limit.to_string());
        if let Some(cursor) = query.cursor.as_deref() {
            push_query(&mut path, &mut first, "cursor", cursor);
        }
        let page: JobPage = self.get_submission(&path).await?;
        if page.api_version != API_VERSION
            || page.items.len() > usize::from(limit)
            || page
                .next_cursor
                .as_deref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
            || page.items.iter().any(|item| !valid_job_summary(item))
            || page
                .items
                .windows(2)
                .any(|pair| pair[0].acceptance_sequence >= pair[1].acceptance_sequence)
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    /// Read one creator-private queued job snapshot.
    pub async fn job(&self, id: &JobId) -> Result<JobSnapshot, ClientError> {
        self.require_submission_capability("jobs.show").await?;
        let snapshot: JobSnapshot = self
            .get_submission(&format!("/v1/jobs/{}", id.as_str()))
            .await?;
        if snapshot.api_version != API_VERSION
            || snapshot.summary.job_id != *id
            || !valid_job_summary(&snapshot.summary)
            || snapshot.attempt_id.is_some()
            || snapshot.result_id.is_some()
            || snapshot.resolved.validate().is_err()
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(snapshot)
    }

    /// List model support records using one validated inventory page.
    pub async fn models(
        &self,
        query: ModelListQuery,
    ) -> Result<InventoryPage<ModelSummary>, ClientError> {
        validate_page_query(&query.page)?;
        if query
            .task_id
            .as_deref()
            .is_some_and(|id| !valid_task_id(id))
            || query
                .task_version
                .as_deref()
                .is_some_and(|version| TaskKey::new("task", version).is_err())
            || (query.task_version.is_some() && query.task_id.is_none())
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = String::from("/v1/models");
        let mut first = true;
        push_page_query(&mut path, &mut first, &query.page);
        if let Some(task_id) = query.task_id.as_deref() {
            push_query(&mut path, &mut first, "task_id", task_id);
        }
        if let Some(task_version) = query.task_version.as_deref() {
            push_query(&mut path, &mut first, "task_version", task_version);
        }
        if let Some(loaded) = query.loaded {
            push_query(
                &mut path,
                &mut first,
                "loaded",
                if loaded { "true" } else { "false" },
            );
        }
        self.check_discovery_operation("models.list").await?;
        let page: InventoryPage<ModelSummary> = self.get(&path).await?;
        validate_page(&page, query.page.limit, |item| {
            valid_public_id(&item.id, "mdl_")
        })?;
        Ok(page)
    }

    /// List the current loaded-model inventory (empty until worker support exists).
    pub async fn models_loaded(
        &self,
        page: PageQuery,
    ) -> Result<InventoryPage<ModelSummary>, ClientError> {
        self.models(ModelListQuery {
            page,
            loaded: Some(true),
            ..Default::default()
        })
        .await
    }

    /// Read one model declaration and its attached schemas.
    pub async fn model(
        &self,
        lookup: ModelLookup,
    ) -> Result<InventoryDetail<ModelDetail>, ClientError> {
        if !valid_model_selector(&lookup.selector)
            || (lookup.task.is_none() && (lookup.runtime_ref.is_some() || lookup.variant.is_some()))
            || lookup
                .runtime_ref
                .as_deref()
                .is_some_and(|value| !valid_runtime_selector(value))
            || lookup
                .variant
                .as_deref()
                .is_some_and(|value| !valid_name(value))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = format!("/v1/models/{}", encode_component(&lookup.selector));
        let mut first = true;
        if let Some(task) = &lookup.task {
            push_query(&mut path, &mut first, "task_id", task.id());
            push_query(&mut path, &mut first, "task_version", task.version());
        }
        if let Some(runtime_ref) = lookup.runtime_ref.as_deref() {
            push_query(&mut path, &mut first, "runtime_ref", runtime_ref);
        }
        if let Some(variant) = lookup.variant.as_deref() {
            push_query(&mut path, &mut first, "variant", variant);
        }
        self.check_discovery_operation("models.show").await?;
        let detail: InventoryDetail<ModelDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if !valid_public_id(&detail.item.summary.id, "mdl_") {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }

    /// List runtime profiles using one validated inventory page.
    pub async fn runtimes(
        &self,
        page: PageQuery,
    ) -> Result<InventoryPage<RuntimeSummary>, ClientError> {
        validate_page_query(&page)?;
        let mut path = String::from("/v1/runtimes");
        let mut first = true;
        push_page_query(&mut path, &mut first, &page);
        self.check_discovery_operation("runtimes.list").await?;
        let page_response: InventoryPage<RuntimeSummary> = self.get(&path).await?;
        validate_page(&page_response, page.limit, |item| {
            valid_public_id(&item.id, "rtp_")
        })?;
        Ok(page_response)
    }

    /// Read one runtime declaration.
    pub async fn runtime(
        &self,
        lookup: RuntimeLookup,
    ) -> Result<InventoryDetail<RuntimeDetail>, ClientError> {
        if !valid_runtime_selector(&lookup.selector) {
            return Err(ClientError::InvalidMaterial);
        }
        self.check_discovery_operation("runtimes.show").await?;
        let path = format!("/v1/runtimes/{}", encode_component(&lookup.selector));
        let detail: InventoryDetail<RuntimeDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if !valid_public_id(&detail.item.summary.id, "rtp_") {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }

    /// List support-specific task bindings using one validated page.
    pub async fn tasks(
        &self,
        query: TaskListQuery,
    ) -> Result<InventoryPage<TaskSummary>, ClientError> {
        validate_page_query(&query.page)?;
        if query
            .support_ref
            .as_deref()
            .is_some_and(|reference| !valid_reference(reference))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = String::from("/v1/tasks");
        let mut first = true;
        push_page_query(&mut path, &mut first, &query.page);
        if let Some(support_ref) = query.support_ref.as_deref() {
            push_query(&mut path, &mut first, "support_ref", support_ref);
        }
        self.check_discovery_operation("tasks.list").await?;
        let page: InventoryPage<TaskSummary> = self.get(&path).await?;
        validate_page(&page, query.page.limit, |item| {
            valid_public_id(&item.id, "tsk_")
        })?;
        Ok(page)
    }

    /// Read one textual task key or one opaque support-specific binding ID.
    pub async fn task(
        &self,
        lookup: TaskLookup,
    ) -> Result<InventoryDetail<TaskDetail>, ClientError> {
        if !valid_task_selector(&lookup.selector)
            || lookup
                .version
                .as_deref()
                .is_some_and(|version| TaskKey::new("task", version).is_err())
            || lookup
                .support_ref
                .as_deref()
                .is_some_and(|reference| !valid_reference(reference))
        {
            return Err(ClientError::InvalidMaterial);
        }
        let mut path = format!("/v1/tasks/{}", encode_component(&lookup.selector));
        let mut first = true;
        if let Some(version) = lookup.version.as_deref() {
            push_query(&mut path, &mut first, "version", version);
        }
        if let Some(support_ref) = lookup.support_ref.as_deref() {
            push_query(&mut path, &mut first, "support_ref", support_ref);
        }
        self.check_discovery_operation("tasks.show").await?;
        let detail: InventoryDetail<TaskDetail> = self.get(&path).await?;
        validate_detail(&detail)?;
        if detail.item.bindings.is_empty()
            || detail
                .item
                .bindings
                .iter()
                .any(|binding| !valid_public_id(&binding.id, "tsk_"))
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(detail)
    }

    async fn check_discovery_operation(&self, operation: &str) -> Result<(), ClientError> {
        let info = self.info().await?;
        validate_discovery_capability(&info.granted_operations, info.discovery.as_ref(), operation)
    }

    async fn require_submission_capability(
        &self,
        operation: &str,
    ) -> Result<SubmissionCapability, ClientError> {
        let info = self.info().await?;
        validate_submission_capability(
            &info.granted_operations,
            info.submission.as_ref(),
            operation,
        )?;
        info.submission
            .ok_or(ClientError::Rejected(ErrorCode::OperationUnavailable))
    }

    async fn get_submission<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        retry_safe_read(
            self.limits.read_attempts,
            self.limits.request_timeout,
            || async {
                let request = self
                    .http
                    .get(format!("{}{}", self.base_url, path))
                    .header(AUTHORIZATION, self.authorization()?);
                let response = request.send().await.map_err(|_| ClientError::Transport)?;
                self.decode_submission_read_response(response).await
            },
        )
        .await
    }

    async fn decode_submission_read_response<T: DeserializeOwned>(
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
        decode_submission_json(&body, self.limits.max_response_bytes)
            .map_err(|_| ClientError::InvalidResponse)
    }

    async fn decode_submission_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, Option<crate::CorrelationId>> {
        let body = read_bounded(response, self.limits.max_response_bytes)
            .await
            .map_err(|_| None)?;
        decode_submission_json(&body, self.limits.max_response_bytes).map_err(|_| None)
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

const SUBMISSION_OPERATIONS: &[&str] = &["inputs.create", "jobs.submit", "jobs.list", "jobs.show"];

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const REQUIRED_SUBMISSION_LIMITS: &[(&str, u64)] = &[
    ("input_bytes_max", 268_435_456),
    ("job_input_bytes_max", 1_073_741_824),
    ("upload_concurrency_max", 2),
    ("staging_reserved_bytes_max", 2_147_483_648),
    ("staged_input_ttl_ms", 86_400_000),
    ("upload_idle_timeout_ms", 30_000),
    ("upload_total_timeout_ms", 600_000),
    ("queued_jobs_max", 128),
    ("submission_bindings_max", 65_536),
    ("submission_binding_bytes_max", 16_384),
    ("captured_input_bytes_max", 17_179_869_184),
    ("storage_free_reserve_bytes", 1_073_741_824),
    ("job_control_bytes_max", 65_536),
    ("job_metadata_bytes_max", 262_144),
    ("job_inputs_max", 64),
    ("job_roles_max", 16),
    ("job_list_default", 20),
    ("job_list_max", 100),
    ("job_cursor_bytes_max", 1_024),
];

const INPUT_CAPTURE_LIMITS: &[(&str, u64)] = &[
    ("input_bytes_max", 268_435_456),
    ("upload_concurrency_max", 2),
    ("staging_reserved_bytes_max", 2_147_483_648),
    ("staged_input_ttl_ms", 86_400_000),
    ("upload_idle_timeout_ms", 30_000),
    ("upload_total_timeout_ms", 600_000),
];

fn validate_submission_capability(
    grants: &[String],
    capability: Option<&SubmissionCapability>,
    operation: &str,
) -> Result<(), ClientError> {
    let Some(capability) = capability else {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    };
    if capability.version != API_VERSION
        || capability.dispatch_enabled
        || capability.limits_source.is_empty()
        || capability.limits_source.len() > 128
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    let provided = capability
        .operations
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = SUBMISSION_OPERATIONS
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if provided.is_empty()
        || provided.len() != capability.operations.len()
        || !provided.is_subset(&expected)
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    if !provided.contains(operation) {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    let required_limits = if provided == ["inputs.create"].into_iter().collect() {
        INPUT_CAPTURE_LIMITS
    } else {
        REQUIRED_SUBMISSION_LIMITS
    };
    if required_limits
        .iter()
        .any(|(key, value)| capability.limits.get(*key).copied() != Some(*value))
        || capability.limits.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 64
                || REQUIRED_SUBMISSION_LIMITS
                    .iter()
                    .find(|(known, _)| key == known)
                    .is_some_and(|(_, expected)| value != expected)
        })
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    if !grants.iter().any(|grant| grant == operation) {
        return Err(ClientError::Rejected(ErrorCode::Forbidden));
    }
    Ok(())
}

async fn stream_input<R>(
    mut source: R,
    length: u64,
    sender: mpsc::Sender<Result<Vec<u8>, io::Error>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut sent = 0_u64;
    while sent < length {
        let capacity = (length - sent).min(INPUT_STREAM_CHUNK_BYTES as u64) as usize;
        let mut chunk = vec![0_u8; capacity];
        let read = match tokio::time::timeout(INPUT_UPLOAD_IDLE_TIMEOUT, source.read(&mut chunk))
            .await
        {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                send_input_stream_error(&sender, error.kind(), "input read failed").await;
                return Err(error);
            }
            Err(_) => {
                send_input_stream_error(&sender, io::ErrorKind::TimedOut, "input read timed out")
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "input read timed out",
                ));
            }
        };
        if read == 0 {
            send_input_stream_error(
                &sender,
                io::ErrorKind::UnexpectedEof,
                "input ended before its declared length",
            )
            .await;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "input ended before its declared length",
            ));
        }
        chunk.truncate(read);
        sent = sent
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "input length overflow"))?;
        if sender.send(Ok(chunk)).await.is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "input stream receiver closed",
            ));
        }
    }

    let mut extra = [0_u8; 1];
    let read = match tokio::time::timeout(INPUT_UPLOAD_IDLE_TIMEOUT, source.read(&mut extra)).await
    {
        Ok(Ok(read)) => read,
        Ok(Err(error)) => {
            send_input_stream_error(&sender, error.kind(), "input EOF check failed").await;
            return Err(error);
        }
        Err(_) => {
            send_input_stream_error(
                &sender,
                io::ErrorKind::TimedOut,
                "input EOF check timed out",
            )
            .await;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "input EOF check timed out",
            ));
        }
    };
    if read != 0 {
        send_input_stream_error(
            &sender,
            io::ErrorKind::InvalidData,
            "input exceeds declared length",
        )
        .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input exceeds declared length",
        ));
    }
    Ok(())
}

async fn send_input_stream_error(
    sender: &mpsc::Sender<Result<Vec<u8>, io::Error>>,
    kind: io::ErrorKind,
    message: &'static str,
) {
    let _ = sender.send(Err(io::Error::new(kind, message))).await;
}

fn valid_job_summary(summary: &crate::JobSummary) -> bool {
    summary.acceptance_sequence >= 1
        && summary.snapshot_revision >= 1
        && summary.state == crate::JobState::Queued
        && summary
            .blockers
            .iter()
            .any(|blocker| blocker == "execution_unavailable")
}

fn validate_discovery_capability(
    grants: &[String],
    capability: Option<&DiscoveryCapability>,
    operation: &str,
) -> Result<(), ClientError> {
    if !grants.iter().any(|grant| grant == "engine.info") {
        return Err(ClientError::Rejected(ErrorCode::Forbidden));
    }
    let Some(capability) = capability else {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    };
    if capability.version != API_VERSION || capability.authorization_grant != "engine.info" {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    if !capability
        .operations
        .iter()
        .any(|provided| provided == operation)
    {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    let expected = [
        "models.list",
        "models.show",
        "runtimes.list",
        "runtimes.show",
        "tasks.list",
        "tasks.show",
    ];
    let provided = capability
        .operations
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if provided.len() != expected.len()
        || expected
            .iter()
            .any(|operation| !provided.contains(operation))
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    Ok(())
}

fn validate_page_query(query: &PageQuery) -> Result<(), ClientError> {
    if query.limit.is_some_and(|limit| !(1..=100).contains(&limit))
        || query
            .cursor
            .as_deref()
            .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
    {
        return Err(ClientError::InvalidMaterial);
    }
    Ok(())
}

fn validate_page<T, F>(
    page: &InventoryPage<T>,
    requested_limit: Option<u8>,
    valid_id: F,
) -> Result<(), ClientError>
where
    F: Fn(&T) -> bool,
{
    page.validate().map_err(|_| ClientError::InvalidResponse)?;
    let maximum = usize::from(requested_limit.unwrap_or(20));
    if page.items.len() > maximum || page.items.iter().any(|item| !valid_id(item)) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

fn validate_detail<T>(detail: &InventoryDetail<T>) -> Result<(), ClientError> {
    if detail.api_version != API_VERSION || !valid_digest(&detail.catalog_revision) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(())
}

fn push_page_query(path: &mut String, first: &mut bool, page: &PageQuery) {
    if let Some(limit) = page.limit {
        push_query(path, first, "limit", &limit.to_string());
    }
    if let Some(cursor) = page.cursor.as_deref() {
        push_query(path, first, "cursor", cursor);
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

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_task_id(value: &str) -> bool {
    valid_name(value)
        && !["mdl_", "rtp_", "tsk_"]
            .iter()
            .any(|prefix| value.starts_with(prefix))
}

fn valid_reference(value: &str) -> bool {
    let Some((name, revision)) = value.split_once('@') else {
        return false;
    };
    valid_name(name) && valid_name(revision)
}

fn valid_model_selector(value: &str) -> bool {
    valid_public_id(value, "mdl_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("mdl_"))
}

fn valid_runtime_selector(value: &str) -> bool {
    valid_public_id(value, "rtp_")
        || valid_reference(value)
        || (valid_name(value) && !value.starts_with("rtp_"))
}

fn valid_task_selector(value: &str) -> bool {
    valid_public_id(value, "tsk_") || valid_task_id(value)
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
