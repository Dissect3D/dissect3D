//! Creator-private result inspection, safe local downloads, and storage
//! inspection through the shared API client (`RP-005`, `RP-P05`, `RP-S13`–`RP-S16`).
//!
//! `dissect3d-cli` remains strictly a client of `dissect3d-api` and
//! `dissect3d-platform`: it never opens SQLite or touches engine-owned storage.
//! [`download_result`] is shared between `results download --output DIR` and
//! `WE-P08`'s foreground `run --output DIR`.

use super::{CommandError, CommandErrorContext, discovery, invalid_error, tokio_runtime};
use crate::config::ConfigFile;
use dissect3d_api::{
    ArtifactStream, Client, ClientError, ClientLimits, ContentDigest, ErrorCode, ResultsQuery,
    StorageMeasurementStatus, StorageSnapshot, VerifiedManifest,
};
use dissect3d_platform::{ClientOutputDirectory, ClientOutputError, OutputFilename};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Maximum single-artifact byte cap enforced by the `rp-0.1` fixture contract.
pub(crate) const FIXTURE_ARTIFACT_CAP_BYTES: u64 = 1_048_576;
const MANIFEST_CHUNK_BYTES: usize = 65_536;
const MANIFEST_FILENAME: &str = "manifest.json";

/// One file verified and atomically installed into the local output directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SavedFile {
    pub(crate) filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) artifact_id: Option<String>,
    pub(crate) byte_length: u64,
    pub(crate) sha256: String,
}

/// Complete local download receipt for one committed result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct DownloadReport {
    pub(crate) result_id: String,
    pub(crate) job_id: String,
    pub(crate) attempt_id: String,
    pub(crate) publication_id: String,
    pub(crate) complete: bool,
    pub(crate) files: Vec<SavedFile>,
}

/// Typed local download failure preserving known job/result identity and any
/// files already installed before the failure (`RP-005`, `RP-S15`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DownloadError {
    pub(crate) category: &'static str,
    pub(crate) message: &'static str,
    pub(crate) exit_code: i32,
    pub(crate) result_id: String,
    pub(crate) job_id: Option<String>,
    pub(crate) completed_files: Vec<SavedFile>,
}

impl DownloadError {
    pub(crate) fn into_command_error(self) -> CommandError {
        let mut data = serde_json::Map::new();
        data.insert(
            "result_id".to_owned(),
            serde_json::Value::String(self.result_id),
        );
        if let Some(job_id) = self.job_id {
            data.insert("job_id".to_owned(), serde_json::Value::String(job_id));
        }
        data.insert("complete".to_owned(), serde_json::Value::Bool(false));
        data.insert(
            "completed_files".to_owned(),
            serde_json::to_value(&self.completed_files)
                .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
        );
        CommandError {
            category: self.category,
            message: self.message,
            exit_code: self.exit_code,
            context: Some(Box::new(CommandErrorContext {
                accepted: None,
                operation_id: None,
                data: Some(serde_json::Value::Object(data)),
                raw_data: None,
            })),
        }
    }
}

/// Result of `storage show`, preserving lossless JSON alongside any diagnostic
/// warnings (including fail-closed reclamation blocks).
pub(crate) struct StorageShowSuccess {
    pub(crate) data: Box<serde_json::value::RawValue>,
    pub(crate) warnings: Vec<String>,
}

/// List one page of committed results (`dissect3d results list`).
pub(crate) fn list(
    limit: Option<u8>,
    cursor: Option<String>,
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<Box<serde_json::value::RawValue>, CommandError> {
    if limit.is_some_and(|value| !(1..=100).contains(&value))
        || cursor
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024)
    {
        return Err(usage_error("Result listing limit or cursor is invalid"));
    }
    discovery::connected(config, path, limits, |client| {
        let page = tokio_runtime()
            .block_on(client.results(ResultsQuery { limit, cursor }))
            .map_err(read_error)?;
        serde_json::value::to_raw_value(&page).map_err(|_| invalid_error())
    })
}

/// Show the exact immutable manifest JSON for one committed result
/// (`dissect3d results show ID`).
pub(crate) fn show(
    result_id: String,
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<Box<serde_json::value::RawValue>, CommandError> {
    if !valid_result_id(&result_id) {
        return Err(usage_error("Result ID is invalid"));
    }
    discovery::connected(config, path, limits, |client| {
        let verified = tokio_runtime()
            .block_on(client.result_manifest(&result_id))
            .map_err(read_error)?;
        let text = String::from_utf8(verified.raw_bytes).map_err(|_| invalid_error())?;
        serde_json::value::RawValue::from_string(text).map_err(|_| invalid_error())
    })
}

/// Verify and save one committed result's files and canonical manifest into
/// `output` without overwriting existing files (`dissect3d results download`).
pub(crate) fn download(
    result_id: String,
    output: PathBuf,
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<DownloadReport, CommandError> {
    if !valid_result_id(&result_id) {
        return Err(usage_error("Result ID is invalid"));
    }
    if output.as_os_str().is_empty() {
        return Err(usage_error("Output directory path is required"));
    }
    discovery::connected(config, path, limits, |client| {
        tokio_runtime()
            .block_on(download_result(&client, &result_id, &output))
            .map_err(DownloadError::into_command_error)
    })
}

/// Show creator-scoped storage usage, limits, and measurement freshness,
/// surfacing fail-closed reclamation blocks as explicit warnings without
/// automatic repair (`dissect3d storage show`).
pub(crate) fn storage_show(
    config: &ConfigFile,
    path: &Path,
    limits: ClientLimits,
) -> Result<StorageShowSuccess, CommandError> {
    discovery::connected(config, path, limits, |client| {
        let snapshot = tokio_runtime()
            .block_on(client.storage())
            .map_err(read_error)?;
        let warnings = storage_warnings(&snapshot);
        let data = serde_json::value::to_raw_value(&snapshot).map_err(|_| invalid_error())?;
        Ok(StorageShowSuccess { data, warnings })
    })
}

trait DownloadStream {
    fn content_length(&self) -> u64;
    fn sha256(&self) -> &ContentDigest;
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ClientError>;
}

impl DownloadStream for ArtifactStream {
    fn content_length(&self) -> u64 {
        ArtifactStream::content_length(self)
    }

    fn sha256(&self) -> &ContentDigest {
        ArtifactStream::sha256(self)
    }

    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        ArtifactStream::next_chunk(self).await
    }
}

trait DownloadSource {
    type Stream: DownloadStream;

    async fn result_manifest(&self, result_id: &str) -> Result<VerifiedManifest, ClientError>;
    async fn artifact(
        &self,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<Self::Stream, ClientError>;
}

impl DownloadSource for Client {
    type Stream = ArtifactStream;

    async fn result_manifest(&self, result_id: &str) -> Result<VerifiedManifest, ClientError> {
        Client::result_manifest(self, result_id).await
    }

    async fn artifact(
        &self,
        artifact_id: &str,
        max_bytes: u64,
    ) -> Result<Self::Stream, ClientError> {
        Client::artifact(self, artifact_id, max_bytes).await
    }
}

/// Reusable safe downloader shared by `results download --output DIR` and
/// `WE-P08` foreground `run --output DIR`.
///
/// Protocol (stage -> digest-verify -> atomic no-replace install):
/// 1. Fetch and verify the canonical manifest via `client.result_manifest`.
/// 2. Validate every manifest filename against destination OS rules, reserve
///    `manifest.json`, and reject any case-insensitive collision.
/// 3. Open/create `destination` with OS-level no-follow confinement.
/// 4. Stream each artifact in `<= 64 KiB` chunks (enforcing the 1 MiB fixture
///    cap), verify exact byte length and SHA-256 independently before atomic
///    no-replace install.
/// 5. Stage `manifest.json` verbatim from `VerifiedManifest.raw_bytes`, verify
///    exact length and SHA-256, and install atomically with no-replace.
/// 6. Any partial staging is cleaned up on drop; existing user files are never
///    modified, and local save failures return exit code `16` without altering
///    committed engine job success.
pub(crate) async fn download_result(
    client: &Client,
    result_id: &str,
    destination: &Path,
) -> Result<DownloadReport, DownloadError> {
    download_result_with(client, result_id, destination).await
}

async fn download_result_with<S: DownloadSource>(
    source: &S,
    result_id: &str,
    destination: &Path,
) -> Result<DownloadReport, DownloadError> {
    if !valid_result_id(result_id) {
        return Err(DownloadError {
            category: "usage_error",
            message: "Result ID is invalid",
            exit_code: 2,
            result_id: result_id.to_owned(),
            job_id: None,
            completed_files: Vec::new(),
        });
    }
    let verified = source
        .result_manifest(result_id)
        .await
        .map_err(|error| manifest_fetch_error(result_id, error))?;
    let job_id = verified.manifest.job_id.as_str().to_owned();
    let mut completed_files = Vec::new();

    // Validate all manifest filenames and reserve `manifest.json` before
    // creating or touching the destination directory.
    let manifest_name = OutputFilename::parse(MANIFEST_FILENAME).map_err(|_| {
        local_save_error(
            result_id,
            &job_id,
            "invalid_output_filename",
            "Manifest filename is invalid for the local destination",
            Vec::new(),
        )
    })?;
    let mut planned: Vec<(OutputFilename, &dissect3d_api::ResultFile)> =
        Vec::with_capacity(verified.manifest.files.len());
    for file in &verified.manifest.files {
        if file.byte_length == 0 || file.byte_length > FIXTURE_ARTIFACT_CAP_BYTES {
            return Err(local_save_error(
                result_id,
                &job_id,
                "transfer_limit",
                "Artifact size exceeds the supported local download limit",
                Vec::new(),
            ));
        }
        let output_name = OutputFilename::parse(&file.filename).map_err(|_| {
            local_save_error(
                result_id,
                &job_id,
                "unsafe_output_filename",
                "Manifest contains an unsafe filename for the local destination",
                Vec::new(),
            )
        })?;
        if output_name.eq_ignore_ascii_case(&manifest_name)
            || planned
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(&output_name))
        {
            return Err(local_save_error(
                result_id,
                &job_id,
                "output_filename_collision",
                "Manifest filenames collide on the local destination",
                Vec::new(),
            ));
        }
        planned.push((output_name, file));
    }

    let directory = ClientOutputDirectory::open(destination)
        .map_err(|error| output_directory_error(result_id, &job_id, error, Vec::new()))?;

    for (output_name, file) in planned {
        let mut stream = source
            .artifact(&file.artifact_id, FIXTURE_ARTIFACT_CAP_BYTES)
            .await
            .map_err(|error| {
                artifact_transfer_error(result_id, &job_id, error, completed_files.clone())
            })?;
        if stream.content_length() != file.byte_length || stream.sha256() != &file.sha256 {
            return Err(local_save_error(
                result_id,
                &job_id,
                "integrity_mismatch",
                "Artifact headers do not match the verified result manifest",
                completed_files,
            ));
        }

        let mut staged = directory.begin_staged_file().map_err(|error| {
            output_directory_error(result_id, &job_id, error, completed_files.clone())
        })?;
        let mut hasher = Sha256::new();
        let mut received: u64 = 0;

        loop {
            let chunk = stream.next_chunk().await.map_err(|error| {
                artifact_transfer_error(result_id, &job_id, error, completed_files.clone())
            })?;
            match chunk {
                Some(bytes) => {
                    let Some(next) = received.checked_add(bytes.len() as u64) else {
                        return Err(local_save_error(
                            result_id,
                            &job_id,
                            "transfer_limit",
                            "Artifact stream exceeded the supported byte limit",
                            completed_files,
                        ));
                    };
                    if next > file.byte_length || next > FIXTURE_ARTIFACT_CAP_BYTES {
                        return Err(local_save_error(
                            result_id,
                            &job_id,
                            "integrity_mismatch",
                            "Artifact stream length exceeded the manifest declaration",
                            completed_files,
                        ));
                    }
                    hasher.update(&bytes);
                    staged.write_chunk(&bytes).map_err(|error| {
                        output_directory_error(result_id, &job_id, error, completed_files.clone())
                    })?;
                    received = next;
                }
                None => break,
            }
        }

        let actual_digest = format_sha256(&hasher.finalize().into());
        if received != file.byte_length || actual_digest != file.sha256.as_str() {
            return Err(local_save_error(
                result_id,
                &job_id,
                "integrity_mismatch",
                "Downloaded artifact bytes did not match the manifest length or SHA-256",
                completed_files,
            ));
        }

        staged.install_no_replace(&output_name).map_err(|error| {
            output_directory_error(result_id, &job_id, error, completed_files.clone())
        })?;

        completed_files.push(SavedFile {
            filename: output_name.as_str().to_owned(),
            artifact_id: Some(file.artifact_id.clone()),
            byte_length: received,
            sha256: actual_digest,
        });
    }

    // Save `manifest.json` verbatim from `VerifiedManifest.raw_bytes` using the
    // exact same private staging, digest verification, and no-replace install.
    let mut staged_manifest = directory.begin_staged_file().map_err(|error| {
        output_directory_error(result_id, &job_id, error, completed_files.clone())
    })?;
    let mut manifest_hasher = Sha256::new();
    for chunk in verified.raw_bytes.chunks(MANIFEST_CHUNK_BYTES) {
        manifest_hasher.update(chunk);
        staged_manifest.write_chunk(chunk).map_err(|error| {
            output_directory_error(result_id, &job_id, error, completed_files.clone())
        })?;
    }
    let manifest_digest = format_sha256(&manifest_hasher.finalize().into());
    if staged_manifest.bytes_written() != verified.raw_bytes.len() as u64
        || manifest_digest != verified.sha256.as_str()
    {
        return Err(local_save_error(
            result_id,
            &job_id,
            "integrity_mismatch",
            "Verified manifest bytes failed local staging integrity check",
            completed_files,
        ));
    }
    staged_manifest
        .install_no_replace(&manifest_name)
        .map_err(|error| {
            output_directory_error(result_id, &job_id, error, completed_files.clone())
        })?;

    completed_files.push(SavedFile {
        filename: MANIFEST_FILENAME.to_owned(),
        artifact_id: None,
        byte_length: verified.raw_bytes.len() as u64,
        sha256: manifest_digest,
    });

    Ok(DownloadReport {
        result_id: verified.manifest.result_id,
        job_id,
        attempt_id: verified.manifest.attempt_id,
        publication_id: verified.manifest.publication_id,
        complete: true,
        files: completed_files,
    })
}

pub(crate) fn storage_warnings(snapshot: &StorageSnapshot) -> Vec<String> {
    let mut warnings = Vec::new();
    match snapshot.measurement.status {
        StorageMeasurementStatus::Current => {}
        StorageMeasurementStatus::Stale => {
            if snapshot.usage.private_staging_bytes.unwrap_or(0) > 0 {
                warnings.push(
                    "storage_reclamation_blocked: private staging bytes remain charged because reclamation is blocked or measurement is stale; no automatic repair is performed"
                        .to_owned(),
                );
            } else {
                warnings.push(
                    "storage_measurement_stale: storage availability or reclamation state is stale"
                        .to_owned(),
                );
            }
        }
        StorageMeasurementStatus::Unavailable => {
            warnings.push(
                "storage_measurement_unavailable: storage usage could not be measured".to_owned(),
            );
        }
    }
    warnings
}

fn valid_result_id(value: &str) -> bool {
    value.strip_prefix("res_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn format_sha256(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn usage_error(message: &'static str) -> CommandError {
    CommandError {
        category: "usage_error",
        message,
        exit_code: 2,
        context: None,
    }
}

fn local_save_error(
    result_id: &str,
    job_id: &str,
    category: &'static str,
    message: &'static str,
    completed_files: Vec<SavedFile>,
) -> DownloadError {
    DownloadError {
        category,
        message,
        exit_code: 16,
        result_id: result_id.to_owned(),
        job_id: Some(job_id.to_owned()),
        completed_files,
    }
}

fn output_directory_error(
    result_id: &str,
    job_id: &str,
    error: ClientOutputError,
    completed_files: Vec<SavedFile>,
) -> DownloadError {
    let (category, message) = match error {
        ClientOutputError::InvalidPath => (
            "invalid_output_path",
            "Local output directory path is invalid",
        ),
        ClientOutputError::InvalidFilename => (
            "unsafe_output_filename",
            "Output filename is unsafe for the local destination",
        ),
        ClientOutputError::UnsafeDestination => (
            "unsafe_output_destination",
            "Local output destination is unsafe or traverses a link",
        ),
        ClientOutputError::AlreadyExists => (
            "output_already_exists",
            "Local output file already exists; existing files are never overwritten",
        ),
        ClientOutputError::PermissionDenied => (
            "local_permission_denied",
            "Permission denied while saving to the local output directory",
        ),
        ClientOutputError::Io | ClientOutputError::UnsupportedPlatform => (
            "local_save_failed",
            "Failed to write or install downloaded output locally",
        ),
    };
    local_save_error(result_id, job_id, category, message, completed_files)
}

fn manifest_fetch_error(result_id: &str, error: ClientError) -> DownloadError {
    let (category, message, exit_code) = match error {
        ClientError::Rejected(ErrorCode::ArtifactUnavailable) => (
            "artifact_unavailable",
            "The committed result manifest or artifact is unavailable on the engine",
            16,
        ),
        ClientError::Rejected(ErrorCode::StorageIntegrityFault) => (
            "storage_integrity_fault",
            "Engine storage integrity check failed for this result",
            16,
        ),
        ClientError::Rejected(
            ErrorCode::Unauthorized
            | ErrorCode::Forbidden
            | ErrorCode::HostDenied
            | ErrorCode::OriginDenied,
        ) => (
            "unauthorized",
            "This profile is not authorized to read this result",
            4,
        ),
        ClientError::Rejected(
            ErrorCode::OperationUnavailable
            | ErrorCode::IncompatibleContract
            | ErrorCode::RequiredFeatureUnsupported,
        )
        | ClientError::Incompatible => (
            "incompatible",
            "The engine result contract or required manifest features are unsupported",
            5,
        ),
        ClientError::Rejected(ErrorCode::NotFound) => {
            ("not_found", "No matching committed result was found", 19)
        }
        ClientError::Rejected(ErrorCode::Busy) => (
            "capacity_rejected",
            "The engine is currently busy; retry later",
            7,
        ),
        ClientError::Transport | ClientError::Rejected(ErrorCode::EngineRecovering) => (
            "engine_unavailable",
            "The authenticated engine request failed",
            3,
        ),
        ClientError::InvalidMaterial | ClientError::Rejected(ErrorCode::InvalidRequest) => {
            ("usage_error", "Result request is invalid", 2)
        }
        ClientError::TransferLimit | ClientError::InvalidResponse | ClientError::Rejected(_) => (
            "artifact_retrieval_failed",
            "The engine returned an invalid or unreadable result manifest",
            16,
        ),
    };
    DownloadError {
        category,
        message,
        exit_code,
        result_id: result_id.to_owned(),
        job_id: None,
        completed_files: Vec::new(),
    }
}

fn artifact_transfer_error(
    result_id: &str,
    job_id: &str,
    error: ClientError,
    completed_files: Vec<SavedFile>,
) -> DownloadError {
    let (category, message, exit_code) = match error {
        ClientError::Rejected(ErrorCode::ArtifactUnavailable) => (
            "artifact_unavailable",
            "The committed artifact is unavailable on the engine",
            16,
        ),
        ClientError::Rejected(ErrorCode::StorageIntegrityFault) => (
            "storage_integrity_fault",
            "Engine storage integrity check failed for this artifact",
            16,
        ),
        ClientError::Rejected(
            ErrorCode::Unauthorized
            | ErrorCode::Forbidden
            | ErrorCode::HostDenied
            | ErrorCode::OriginDenied,
        ) => (
            "unauthorized",
            "This profile is not authorized to read this artifact",
            4,
        ),
        ClientError::TransferLimit => (
            "transfer_limit",
            "Artifact exceeded the supported local download size limit",
            16,
        ),
        ClientError::InvalidResponse => (
            "integrity_mismatch",
            "Artifact transfer failed length or SHA-256 verification",
            16,
        ),
        ClientError::Transport | ClientError::Rejected(_) | ClientError::Incompatible => (
            "artifact_retrieval_failed",
            "Artifact download was interrupted before completion",
            16,
        ),
        ClientError::InvalidMaterial => (
            "artifact_retrieval_failed",
            "Manifest artifact reference is invalid",
            16,
        ),
    };
    DownloadError {
        category,
        message,
        exit_code,
        result_id: result_id.to_owned(),
        job_id: Some(job_id.to_owned()),
        completed_files,
    }
}

fn read_error(error: ClientError) -> CommandError {
    match error {
        ClientError::Rejected(
            ErrorCode::Unauthorized
            | ErrorCode::Forbidden
            | ErrorCode::HostDenied
            | ErrorCode::OriginDenied,
        ) => CommandError {
            category: "unauthorized",
            message: "This profile is not authorized for this result operation",
            exit_code: 4,
            context: None,
        },
        ClientError::Rejected(
            ErrorCode::OperationUnavailable
            | ErrorCode::IncompatibleContract
            | ErrorCode::RequiredFeatureUnsupported,
        )
        | ClientError::Incompatible => CommandError {
            category: "incompatible",
            message: "The engine does not support this result operation or manifest feature",
            exit_code: 5,
            context: None,
        },
        ClientError::Rejected(ErrorCode::NotFound) => CommandError {
            category: "not_found",
            message: "No matching committed result was found",
            exit_code: 19,
            context: None,
        },
        ClientError::Rejected(ErrorCode::JobCursorExpired) => CommandError {
            category: "job_cursor_expired",
            message: "The result listing cursor expired; start a fresh listing",
            exit_code: 19,
            context: None,
        },
        ClientError::Rejected(ErrorCode::ArtifactUnavailable) => CommandError {
            category: "artifact_unavailable",
            message: "The committed result manifest or artifact is unavailable",
            exit_code: 16,
            context: None,
        },
        ClientError::Rejected(ErrorCode::StorageIntegrityFault) => CommandError {
            category: "storage_integrity_fault",
            message: "Engine storage integrity check failed for this result",
            exit_code: 16,
            context: None,
        },
        ClientError::Rejected(ErrorCode::Busy) => CommandError {
            category: "capacity_rejected",
            message: "The engine could not admit the requested read",
            exit_code: 7,
            context: None,
        },
        ClientError::Rejected(ErrorCode::InvalidRequest) | ClientError::InvalidMaterial => {
            usage_error("Result request is invalid")
        }
        ClientError::Transport | ClientError::Rejected(ErrorCode::EngineRecovering) => {
            CommandError {
                category: "engine_unavailable",
                message: "The authenticated engine request failed",
                exit_code: 3,
                context: None,
            }
        }
        ClientError::TransferLimit | ClientError::InvalidResponse | ClientError::Rejected(_) => {
            invalid_error()
        }
    }
}

#[cfg(test)]
#[path = "results_tests.rs"]
mod tests;
