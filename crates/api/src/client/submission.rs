//! Input capture and job submission/read operations, with their capability and
//! limit checks.

use super::*;

impl Client {
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
        self.create_input_inner(source, length, media_type, maximum, false)
            .await
    }

    pub(super) async fn create_input_inner<R>(
        &self,
        source: R,
        length: u64,
        media_type: &str,
        maximum: u64,
        execution: bool,
    ) -> Result<InputReceipt, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
    {
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
        let mut request = self
            .upload_http
            .post(format!("{}/v1/inputs", self.base_url))
            .header(AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_TYPE, media_type.as_str())
            .header(reqwest::header::CONTENT_LENGTH, length)
            .timeout(INPUT_UPLOAD_TOTAL_TIMEOUT)
            .body(body);
        if execution {
            request = request.header(crate::JOB_CONTRACT_HEADER, crate::JOB_CONTRACT);
        }
        let response = request.send().await;

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
}

impl Client {
    pub(super) async fn require_submission_capability(
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

    pub(super) async fn get_submission<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ClientError> {
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

    pub(super) async fn decode_submission_read_response<T: DeserializeOwned>(
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

    pub(super) async fn decode_submission_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, Option<crate::CorrelationId>> {
        let body = read_bounded(response, self.limits.max_response_bytes)
            .await
            .map_err(|_| None)?;
        decode_submission_json(&body, self.limits.max_response_bytes).map_err(|_| None)
    }
}

pub(super) const SUBMISSION_OPERATIONS: &[&str] =
    &["inputs.create", "jobs.submit", "jobs.list", "jobs.show"];

pub(super) struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) const REQUIRED_SUBMISSION_LIMITS: &[(&str, u64)] = &[
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

pub(super) const INPUT_CAPTURE_LIMITS: &[(&str, u64)] = &[
    ("input_bytes_max", 268_435_456),
    ("upload_concurrency_max", 2),
    ("staging_reserved_bytes_max", 2_147_483_648),
    ("staged_input_ttl_ms", 86_400_000),
    ("upload_idle_timeout_ms", 30_000),
    ("upload_total_timeout_ms", 600_000),
];

pub(super) fn validate_submission_capability(
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

pub(super) async fn stream_input<R>(
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

pub(super) async fn send_input_stream_error(
    sender: &mpsc::Sender<Result<Vec<u8>, io::Error>>,
    kind: io::ErrorKind,
    message: &'static str,
) {
    let _ = sender.send(Err(io::Error::new(kind, message))).await;
}

pub(super) fn valid_job_summary(summary: &crate::JobSummary) -> bool {
    summary.acceptance_sequence >= 1
        && summary.snapshot_revision >= 1
        && summary.state == crate::JobState::Queued
        && summary
            .blockers
            .iter()
            .any(|blocker| blocker == "execution_unavailable")
}
