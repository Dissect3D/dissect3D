//! Negotiated execution client. Runtime route activation is engine-owned.
use super::*;
use crate::{
    CancelResponse, ExecutionAcceptance, ExecutionCapability, ExecutionEngineInfo,
    ExecutionJobPage, ExecutionJobSnapshot, ExecutionRecord, ExecutionSubmissionBody, JOB_CONTRACT,
    JOB_CONTRACT_HEADER, decode_execution_json,
};

impl Client {
    /// Non-failing `/v1/info` probe returning `ExecutionEngineInfo`.
    ///
    /// When `job_execution` is absent, returns `Ok(info)` with `job_execution: None`
    /// so callers can select Stage 3 vs negotiated `we-0.1` mode without failing.
    /// When `job_execution` is present, validates its contract and `dispatch_enabled`
    /// consistency once.
    pub async fn execution_info(&self) -> Result<ExecutionEngineInfo, ClientError> {
        let info: ExecutionEngineInfo = self.get_submission("/v1/info").await?;
        if info.core.api_version != API_VERSION
            || !info.core.required_features.is_empty()
            || info.core.installation_id != self.installation_id
            || info.core.instance_id != self.instance_id
        {
            return Err(ClientError::Incompatible);
        }
        if let Some(capability) = &info.job_execution {
            capability
                .validate()
                .map_err(|_| ClientError::Rejected(ErrorCode::IncompatibleContract))?;
            let submission = info
                .core
                .submission
                .as_ref()
                .ok_or(ClientError::Rejected(ErrorCode::IncompatibleContract))?;
            if submission.dispatch_enabled != capability.dispatch_enabled {
                return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
            }
        }
        Ok(info)
    }

    pub async fn create_execution_input<R>(
        &self,
        source: R,
        length: u64,
        media_type: &str,
    ) -> Result<InputReceipt, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        let cap = self.require_execution_capability("inputs.create").await?;
        self.create_execution_input_with(&cap, source, length, media_type)
            .await
    }

    pub async fn create_execution_input_with<R>(
        &self,
        capability: &ExecutionCapability,
        source: R,
        length: u64,
        media_type: &str,
    ) -> Result<InputReceipt, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
        require_operation(capability, "inputs.create")?;
        self.create_input_inner(source, length, media_type, MAX_INPUT_BYTES, true)
            .await
    }

    /// Call before opening/capturing fresh inputs. Missing/unknown semantics fail
    /// before a mutation; old core and discovery methods keep their own contracts.
    pub async fn require_execution_capability(
        &self,
        operation: &str,
    ) -> Result<ExecutionCapability, ClientError> {
        let info = self.execution_info().await?;
        validate_execution_capability(&info, operation)?;
        info.job_execution
            .ok_or(ClientError::Rejected(ErrorCode::OperationUnavailable))
    }

    /// Single send of exact captured bytes, including unchanged legacy replay.
    /// A legacy body here is replay-only; binding-first refusal is Store-owned.
    pub async fn submit_execution_job(
        &self,
        key: &IdempotencyKey,
        body: &ExecutionSubmissionBody,
    ) -> Result<ExecutionAcceptance, SubmissionClientError> {
        let cap = self
            .require_execution_capability("jobs.submit")
            .await
            .map_err(SubmissionClientError::BeforeSend)?;
        self.submit_execution_job_with(&cap, key, body).await
    }

    pub async fn submit_execution_job_with(
        &self,
        capability: &ExecutionCapability,
        key: &IdempotencyKey,
        body: &ExecutionSubmissionBody,
    ) -> Result<ExecutionAcceptance, SubmissionClientError> {
        require_operation(capability, "jobs.submit").map_err(SubmissionClientError::BeforeSend)?;
        let receipt: ExecutionAcceptance = self
            .post_execution("/v1/jobs", Some(key), body.as_bytes(), true)
            .await?;
        if receipt.retry_of.is_some() {
            return Err(SubmissionClientError::Uncertain {
                correlation_id: None,
            });
        }
        Ok(receipt)
    }

    pub async fn execution_job(&self, id: &JobId) -> Result<ExecutionJobSnapshot, ClientError> {
        let cap = self.require_execution_capability("jobs.show").await?;
        self.execution_job_with(&cap, id).await
    }

    pub async fn execution_job_with(
        &self,
        capability: &ExecutionCapability,
        id: &JobId,
    ) -> Result<ExecutionJobSnapshot, ClientError> {
        require_operation(capability, "jobs.show")?;
        let snapshot: ExecutionJobSnapshot = self
            .get_execution(&format!("/v1/jobs/{}", id.as_str()))
            .await?;
        if snapshot.summary.job_id != *id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(snapshot)
    }

    pub async fn execution_jobs(&self, query: JobsQuery) -> Result<ExecutionJobPage, ClientError> {
        let cap = self.require_execution_capability("jobs.list").await?;
        self.execution_jobs_with(&cap, query).await
    }

    pub async fn execution_jobs_with(
        &self,
        capability: &ExecutionCapability,
        query: JobsQuery,
    ) -> Result<ExecutionJobPage, ClientError> {
        let limit = query.limit.unwrap_or(20);
        if !(1..=100).contains(&limit)
            || query
                .cursor
                .as_ref()
                .is_some_and(|c| c.is_empty() || c.len() > 1024)
        {
            return Err(ClientError::InvalidMaterial);
        }
        require_operation(capability, "jobs.list")?;
        let mut path = "/v1/jobs".to_owned();
        let mut first = true;
        push_query(&mut path, &mut first, "limit", &limit.to_string());
        if let Some(cursor) = query.cursor {
            push_query(&mut path, &mut first, "cursor", &cursor);
        }
        let page: ExecutionJobPage = self.get_execution(&path).await?;
        if page.items.len() > usize::from(limit) {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    pub async fn cancel_execution_job(
        &self,
        id: &JobId,
    ) -> Result<CancelResponse, SubmissionClientError> {
        let cap = self
            .require_execution_capability("jobs.cancel")
            .await
            .map_err(SubmissionClientError::BeforeSend)?;
        self.cancel_execution_job_with(&cap, id).await
    }

    pub async fn cancel_execution_job_with(
        &self,
        capability: &ExecutionCapability,
        id: &JobId,
    ) -> Result<CancelResponse, SubmissionClientError> {
        require_operation(capability, "jobs.cancel").map_err(SubmissionClientError::BeforeSend)?;
        let response: CancelResponse = self
            .post_execution(
                &format!("/v1/jobs/{}/cancel", id.as_str()),
                None,
                br#"{"api_version":"1.0","required_features":[]}"#,
                false,
            )
            .await?;
        if response.job_snapshot.summary.job_id != *id {
            return Err(SubmissionClientError::Uncertain {
                correlation_id: None,
            });
        }
        Ok(response)
    }

    pub async fn retry_execution_job(
        &self,
        id: &JobId,
        key: &IdempotencyKey,
    ) -> Result<ExecutionAcceptance, SubmissionClientError> {
        let cap = self
            .require_execution_capability("jobs.retry")
            .await
            .map_err(SubmissionClientError::BeforeSend)?;
        self.retry_execution_job_with(&cap, id, key).await
    }

    pub async fn retry_execution_job_with(
        &self,
        capability: &ExecutionCapability,
        id: &JobId,
        key: &IdempotencyKey,
    ) -> Result<ExecutionAcceptance, SubmissionClientError> {
        require_operation(capability, "jobs.retry").map_err(SubmissionClientError::BeforeSend)?;
        let receipt: ExecutionAcceptance = self
            .post_execution(
                &format!("/v1/jobs/{}/retry", id.as_str()),
                Some(key),
                br#"{"api_version":"1.0","required_features":[]}"#,
                true,
            )
            .await?;
        if receipt.retry_of.as_ref() != Some(id) || receipt.job_id == *id {
            return Err(SubmissionClientError::Uncertain {
                correlation_id: None,
            });
        }
        Ok(receipt)
    }

    async fn get_execution<T: ExecutionRecord>(&self, path: &str) -> Result<T, ClientError> {
        retry_safe_read(
            self.limits.read_attempts,
            self.limits.request_timeout,
            || async {
                let response = self
                    .http
                    .get(format!("{}{}", self.base_url, path))
                    .header(AUTHORIZATION, self.authorization()?)
                    .header(JOB_CONTRACT_HEADER, JOB_CONTRACT)
                    .send()
                    .await
                    .map_err(|_| ClientError::Transport)?;
                let status = response.status();
                let body = read_bounded(response, self.limits.max_response_bytes).await?;
                if status != reqwest::StatusCode::OK {
                    let error: ApiError =
                        decode_json(&body).map_err(|_| ClientError::InvalidResponse)?;
                    if error.api_version != API_VERSION {
                        return Err(ClientError::Incompatible);
                    }
                    return Err(ClientError::Rejected(error.error.code));
                }
                decode_execution_json(&body, self.limits.max_response_bytes)
                    .map_err(|_| ClientError::InvalidResponse)
            },
        )
        .await
    }

    async fn post_execution<T: ExecutionRecord>(
        &self,
        path: &str,
        key: Option<&IdempotencyKey>,
        body: &[u8],
        acceptance: bool,
    ) -> Result<T, SubmissionClientError> {
        let uncertain = || SubmissionClientError::Uncertain {
            correlation_id: None,
        };
        let mut request = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .header(
                AUTHORIZATION,
                self.authorization()
                    .map_err(SubmissionClientError::BeforeSend)?,
            )
            .header(JOB_CONTRACT_HEADER, JOB_CONTRACT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec());
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key.as_str());
        }
        let response = request.send().await.map_err(|_| uncertain())?;
        let status = response.status();
        let body = read_bounded(response, self.limits.max_response_bytes)
            .await
            .map_err(|_| uncertain())?;
        if !status.is_success() {
            let error: ApiError = decode_json(&body).map_err(|_| uncertain())?;
            if error.api_version != API_VERSION {
                return Err(uncertain());
            }
            return Err(SubmissionClientError::Rejected(Box::new(error)));
        }
        if status != reqwest::StatusCode::OK
            && !(acceptance && status == reqwest::StatusCode::CREATED)
        {
            return Err(uncertain());
        }
        if acceptance {
            let receipt: ExecutionAcceptance =
                decode_execution_json(&body, self.limits.max_response_bytes)
                    .map_err(|_| uncertain())?;
            if receipt.replayed != (status == reqwest::StatusCode::OK) {
                return Err(uncertain());
            }
        }
        decode_execution_json(&body, self.limits.max_response_bytes).map_err(|_| uncertain())
    }
}

fn require_operation(capability: &ExecutionCapability, operation: &str) -> Result<(), ClientError> {
    capability
        .validate()
        .map_err(|_| ClientError::Rejected(ErrorCode::IncompatibleContract))?;
    if !capability.operations.iter().any(|s| s == operation) {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    Ok(())
}

pub(super) fn validate_execution_capability(
    info: &ExecutionEngineInfo,
    operation: &str,
) -> Result<(), ClientError> {
    let capability = info
        .job_execution
        .as_ref()
        .ok_or(ClientError::Rejected(ErrorCode::OperationUnavailable))?;
    capability
        .validate()
        .map_err(|_| ClientError::Rejected(ErrorCode::IncompatibleContract))?;
    let submission = info
        .core
        .submission
        .as_ref()
        .ok_or(ClientError::Rejected(ErrorCode::IncompatibleContract))?;
    if submission.dispatch_enabled != capability.dispatch_enabled {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    // Validate existing admission bounds/grants without weakening the legacy guard.
    if ["jobs.submit", "jobs.list", "jobs.show", "inputs.create"].contains(&operation) {
        let mut queued = submission.clone();
        queued.dispatch_enabled = false;
        validate_submission_capability(&info.core.granted_operations, Some(&queued), operation)?;
    }
    if !capability.operations.iter().any(|s| s == operation) {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    if !info.core.granted_operations.iter().any(|s| s == operation) {
        return Err(ClientError::Rejected(ErrorCode::Forbidden));
    }
    Ok(())
}
