//! Shared typed client for creator-private result publication reads (`RP-004`).
//!
//! All methods verify `EngineInfo.result_publication` before issuing a route
//! request, enforce finite response and streaming bounds, and return safe
//! `ClientError` categories without leaking raw transport or path details.

use super::*;
use crate::{
    ContentDigest, MANIFEST_BYTES_MAX, RESULT_FEATURE, ResultManifest, ResultPage,
    ResultPublicationCapability, ResultsQuery, StorageSnapshot, decode_result_manifest,
    decode_result_page, decode_storage_snapshot,
};
use reqwest::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use std::collections::VecDeque;

const RESULT_CONTRACT: &str = "rp-0.1";
const ARTIFACT_STREAM_CHUNK_BYTES: usize = 65_536;
const X_CONTENT_SHA256: &str = "x-content-sha256";

/// Canonical manifest decoded and verified against its exact wire bytes.
///
/// `raw_bytes` preserves the exact immutable engine bytes so clients (such as
/// `RP-P05` local downloads) can persist `manifest.json` verbatim without
/// re-serializing.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedManifest {
    pub manifest: ResultManifest,
    pub raw_bytes: Vec<u8>,
    pub sha256: ContentDigest,
}

/// Bounded, backpressure-aware stream of one published artifact's bytes.
///
/// Each [`next_chunk`](Self::next_chunk) call yields at most 64 KiB, enforces
/// `Content-Length` and the caller's byte cap incrementally, and verifies the
/// final byte count and `X-Content-SHA256` digest at EOF.
pub struct ArtifactStream {
    response: reqwest::Response,
    content_length: u64,
    sha256: ContentDigest,
    media_type: String,
    filename: Option<String>,
    received: u64,
    max_bytes: u64,
    chunk_timeout: Duration,
    hasher: Sha256,
    pending: VecDeque<Vec<u8>>,
    finished: bool,
}

impl ArtifactStream {
    pub fn content_length(&self) -> u64 {
        self.content_length
    }

    pub fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Read the next verified chunk (at most 64 KiB), or `None` after EOF
    /// length and SHA-256 verification succeed.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        if let Some(chunk) = self.pending.pop_front() {
            return Ok(Some(chunk));
        }
        if self.finished {
            return Ok(None);
        }
        loop {
            let next = tokio::time::timeout(self.chunk_timeout, self.response.chunk())
                .await
                .map_err(|_| ClientError::Transport)?
                .map_err(|_| ClientError::Transport)?;
            match next {
                Some(chunk) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    let next_total = self
                        .received
                        .checked_add(chunk.len() as u64)
                        .ok_or(ClientError::TransferLimit)?;
                    if next_total > self.max_bytes {
                        self.finished = true;
                        return Err(ClientError::TransferLimit);
                    }
                    if next_total > self.content_length {
                        self.finished = true;
                        return Err(ClientError::InvalidResponse);
                    }
                    self.received = next_total;
                    self.hasher.update(&chunk);
                    for slice in chunk.chunks(ARTIFACT_STREAM_CHUNK_BYTES) {
                        self.pending.push_back(slice.to_vec());
                    }
                    return Ok(self.pending.pop_front());
                }
                None => {
                    self.finished = true;
                    if self.received != self.content_length {
                        return Err(ClientError::InvalidResponse);
                    }
                    let digest: [u8; 32] = self.hasher.clone().finalize().into();
                    let actual = format_sha256(&digest);
                    if actual != self.sha256.as_str() {
                        return Err(ClientError::InvalidResponse);
                    }
                    return Ok(None);
                }
            }
        }
    }
}

impl Client {
    /// Verify `EngineInfo.result_publication` and the client's grant for
    /// `operation` before calling any result or storage read route.
    pub async fn require_result_publication_capability(
        &self,
        operation: &str,
    ) -> Result<ResultPublicationCapability, ClientError> {
        let info = self.info().await?;
        validate_result_publication_capability(&info, operation)?;
        info.result_publication
            .ok_or(ClientError::Rejected(ErrorCode::OperationUnavailable))
    }

    /// List one creator-scoped page of committed results (`GET /v1/results`).
    pub async fn results(&self, query: ResultsQuery) -> Result<ResultPage, ClientError> {
        let limit = query.limit.unwrap_or(20);
        if !(1..=100).contains(&limit)
            || query
                .cursor
                .as_ref()
                .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 1024)
        {
            return Err(ClientError::InvalidMaterial);
        }
        self.require_result_publication_capability("results.list")
            .await?;
        let mut path = "/v1/results".to_owned();
        let mut first = true;
        push_query(&mut path, &mut first, "limit", &limit.to_string());
        if let Some(cursor) = query.cursor {
            push_query(&mut path, &mut first, "cursor", &cursor);
        }
        let body = self
            .get_result_bytes(&path, self.limits.max_response_bytes)
            .await?;
        let page = decode_result_page(&body).map_err(|_| ClientError::InvalidResponse)?;
        if page.items.len() > usize::from(limit) {
            return Err(ClientError::InvalidResponse);
        }
        Ok(page)
    }

    /// Read one creator-scoped canonical manifest (`GET /v1/results/{id}/manifest`).
    pub async fn result_manifest(&self, result_id: &str) -> Result<VerifiedManifest, ClientError> {
        if !valid_result_id(result_id, "res_") {
            return Err(ClientError::InvalidMaterial);
        }
        self.require_result_publication_capability("results.show")
            .await?;
        let path = format!("/v1/results/{result_id}/manifest");
        let max_bytes = self.limits.max_response_bytes.min(MANIFEST_BYTES_MAX);
        let (headers, raw_bytes) = self.get_result_response(&path, max_bytes).await?;
        let media = single_header_str(&headers, CONTENT_TYPE.as_str())
            .ok_or(ClientError::InvalidResponse)?;
        if !media.eq_ignore_ascii_case("application/json") {
            return Err(ClientError::InvalidResponse);
        }
        if let Some(raw_len) = single_header_str(&headers, CONTENT_LENGTH.as_str()) {
            let declared: usize = raw_len.parse().map_err(|_| ClientError::InvalidResponse)?;
            if declared != raw_bytes.len() {
                return Err(ClientError::InvalidResponse);
            }
        }
        let digest: [u8; 32] = Sha256::digest(&raw_bytes).into();
        let sha256 = ContentDigest::parse(format_sha256(&digest))
            .map_err(|_| ClientError::InvalidResponse)?;
        if let Some(header_digest) = single_header_str(&headers, X_CONTENT_SHA256) {
            let expected =
                ContentDigest::parse(header_digest).map_err(|_| ClientError::InvalidResponse)?;
            if expected != sha256 {
                return Err(ClientError::InvalidResponse);
            }
        }
        let manifest = match decode_result_manifest(&raw_bytes) {
            Ok(manifest) => manifest,
            Err(_) => {
                if has_unsupported_manifest_feature(&raw_bytes) {
                    return Err(ClientError::Incompatible);
                }
                return Err(ClientError::InvalidResponse);
            }
        };
        if manifest.result_id != result_id {
            return Err(ClientError::InvalidResponse);
        }
        Ok(VerifiedManifest {
            manifest,
            raw_bytes,
            sha256,
        })
    }

    /// Open a bounded, verified stream for one published artifact
    /// (`GET /v1/artifacts/{id}`).
    pub async fn artifact(
        &self,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<ArtifactStream, ClientError> {
        if !valid_result_id(artifact_id, "art_") || max_bytes == 0 {
            return Err(ClientError::InvalidMaterial);
        }
        self.require_result_publication_capability("artifacts.read")
            .await?;
        let path = format!("/v1/artifacts/{artifact_id}");
        let response = self
            .upload_http
            .get(format!("{}{}", self.base_url, path))
            .header(AUTHORIZATION, self.authorization()?)
            .send()
            .await
            .map_err(|_| ClientError::Transport)?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            let body = read_bounded(response, self.limits.max_response_bytes).await?;
            let error: ApiError = decode_json(&body).map_err(|_| ClientError::InvalidResponse)?;
            if error.api_version != API_VERSION {
                return Err(ClientError::Incompatible);
            }
            return Err(ClientError::Rejected(error.error.code));
        }
        let headers = response.headers();
        let raw_length = single_header_str(headers, CONTENT_LENGTH.as_str())
            .ok_or(ClientError::InvalidResponse)?;
        if raw_length.is_empty() || !raw_length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ClientError::InvalidResponse);
        }
        let content_length: u64 = raw_length
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;
        if content_length == 0 {
            return Err(ClientError::InvalidResponse);
        }
        if content_length > max_bytes {
            return Err(ClientError::TransferLimit);
        }
        let raw_digest =
            single_header_str(headers, X_CONTENT_SHA256).ok_or(ClientError::InvalidResponse)?;
        let sha256 = ContentDigest::parse(raw_digest).map_err(|_| ClientError::InvalidResponse)?;
        let media_type = single_header_str(headers, CONTENT_TYPE.as_str())
            .ok_or(ClientError::InvalidResponse)?;
        if !valid_media_type(media_type) {
            return Err(ClientError::InvalidResponse);
        }
        let media_type = media_type.to_owned();
        let disposition = single_header_str(headers, CONTENT_DISPOSITION.as_str())
            .ok_or(ClientError::InvalidResponse)?;
        let filename = parse_attachment_disposition(disposition)?;
        Ok(ArtifactStream {
            response,
            content_length,
            sha256,
            media_type,
            filename,
            received: 0,
            max_bytes,
            chunk_timeout: self.limits.request_timeout,
            hasher: Sha256::new(),
            pending: VecDeque::new(),
            finished: false,
        })
    }

    /// Read creator-scoped storage usage and engine capacity constraints
    /// (`GET /v1/storage`).
    pub async fn storage(&self) -> Result<StorageSnapshot, ClientError> {
        self.require_result_publication_capability("storage.show")
            .await?;
        let body = self
            .get_result_bytes("/v1/storage", self.limits.max_response_bytes)
            .await?;
        decode_storage_snapshot(&body).map_err(|_| ClientError::InvalidResponse)
    }

    async fn get_result_bytes(&self, path: &str, maximum: usize) -> Result<Vec<u8>, ClientError> {
        let (_, body) = self.get_result_response(path, maximum).await?;
        Ok(body)
    }

    async fn get_result_response(
        &self,
        path: &str,
        maximum: usize,
    ) -> Result<(reqwest::header::HeaderMap, Vec<u8>), ClientError> {
        retry_safe_read(
            self.limits.read_attempts,
            self.limits.request_timeout,
            || async {
                let response = self
                    .http
                    .get(format!("{}{}", self.base_url, path))
                    .header(AUTHORIZATION, self.authorization()?)
                    .send()
                    .await
                    .map_err(|_| ClientError::Transport)?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = read_bounded(response, maximum).await?;
                if status != reqwest::StatusCode::OK {
                    let error: ApiError =
                        decode_json(&body).map_err(|_| ClientError::InvalidResponse)?;
                    if error.api_version != API_VERSION {
                        return Err(ClientError::Incompatible);
                    }
                    return Err(ClientError::Rejected(error.error.code));
                }
                Ok((headers, body))
            },
        )
        .await
    }
}

pub(super) fn validate_result_publication_capability(
    info: &EngineInfo,
    operation: &str,
) -> Result<(), ClientError> {
    let capability = info
        .result_publication
        .as_ref()
        .ok_or(ClientError::Rejected(ErrorCode::OperationUnavailable))?;
    if capability.contract_version != RESULT_CONTRACT
        || capability.limits.is_empty()
        || capability.limits.len() > 128
        || capability.operations.len() > 32
        || capability.required_features != [RESULT_FEATURE]
    {
        return Err(ClientError::Rejected(ErrorCode::IncompatibleContract));
    }
    if !capability.operations.iter().any(|item| item == operation) {
        return Err(ClientError::Rejected(ErrorCode::OperationUnavailable));
    }
    if !info.granted_operations.iter().any(|item| item == operation) {
        return Err(ClientError::Rejected(ErrorCode::Forbidden));
    }
    Ok(())
}

fn valid_result_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn single_header_str<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

fn parse_attachment_disposition(value: &str) -> Result<Option<String>, ClientError> {
    let mut parts = value.split(';').map(str::trim);
    let kind = parts.next().ok_or(ClientError::InvalidResponse)?;
    if !kind.eq_ignore_ascii_case("attachment") {
        return Err(ClientError::InvalidResponse);
    }
    for param in parts {
        if let Some(rest) = param.strip_prefix("filename=") {
            let unquoted = rest
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(rest);
            if !unquoted.is_empty() {
                return Ok(Some(unquoted.to_owned()));
            }
        }
    }
    Ok(None)
}

fn format_sha256(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(hex_digit(byte >> 4)));
        out.push(char::from(hex_digit(byte & 0x0f)));
    }
    out
}

fn has_unsupported_manifest_feature(bytes: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct ManifestHeader {
        #[serde(default)]
        manifest_version: Option<String>,
        #[serde(default)]
        required_features: Option<Vec<String>>,
    }
    let Ok(header) = crate::decode_submission_json::<ManifestHeader>(bytes, MANIFEST_BYTES_MAX)
    else {
        return false;
    };
    if header
        .manifest_version
        .as_deref()
        .is_some_and(|version| version != "1.0")
    {
        return true;
    }
    header
        .required_features
        .is_some_and(|features| features.iter().any(|feature| feature != RESULT_FEATURE))
}

#[cfg(test)]
#[path = "results_tests.rs"]
mod tests;
