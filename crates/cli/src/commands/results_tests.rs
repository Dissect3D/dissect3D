//! Unit tests for CLI result ID validation, storage reclamation-block warnings,
//! exit-16 failure context mapping, and end-to-end `download_result_with`
//! staging/verification/no-replace behavior (`RP-P05`, `RP-S13`–`RP-S15`).

use super::*;
use dissect3d_api::{StorageMeasurement, StorageUsage, decode_result_manifest};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use tempfile::TempDir;

const RESULT_ID: &str = "res_11111111111111111111111111111111";
const JOB_ID: &str = "job_22222222222222222222222222222222";
const ARTIFACT_ID: &str = "art_55555555555555555555555555555555";

struct FakeStream {
    content_length: u64,
    sha256: ContentDigest,
    chunks: VecDeque<Result<Vec<u8>, ClientError>>,
}

impl DownloadStream for FakeStream {
    fn content_length(&self) -> u64 {
        self.content_length
    }

    fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }

    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        match self.chunks.pop_front() {
            Some(Ok(bytes)) => Ok(Some(bytes)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }
}

struct FakeSource {
    manifest: VerifiedManifest,
    stream_len: u64,
    stream_sha: ContentDigest,
    chunks: Vec<Result<Vec<u8>, ClientError>>,
}

impl FakeSource {
    fn for_bytes(artifact_bytes: &[u8]) -> Self {
        let sha_hex = format_sha256(&Sha256::digest(artifact_bytes).into());
        let mut value: serde_json::Value = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../api/tests/fixtures/result_publication.json"
        ))
        .unwrap()["complete_mesh_copy"]
            .clone();
        value["files"][0]["byte_length"] = serde_json::json!(artifact_bytes.len());
        value["files"][0]["sha256"] = serde_json::json!(sha_hex);
        value["provenance"]["resolved"]["inputs"]["mesh"][0]["byte_length"] =
            serde_json::json!(artifact_bytes.len());
        value["provenance"]["resolved"]["inputs"]["mesh"][0]["sha256"] = serde_json::json!(sha_hex);
        value["provenance"]["input_identities"][0]["byte_length"] =
            serde_json::json!(artifact_bytes.len());
        value["provenance"]["input_identities"][0]["sha256"] = serde_json::json!(sha_hex);
        let raw_bytes = serde_json::to_vec(&value).unwrap();
        let manifest = decode_result_manifest(&raw_bytes).unwrap();
        let manifest_sha =
            ContentDigest::parse(format_sha256(&Sha256::digest(&raw_bytes).into())).unwrap();
        let stream_sha = ContentDigest::parse(sha_hex).unwrap();
        let chunks = artifact_bytes
            .chunks(65_536)
            .map(|chunk| Ok(chunk.to_vec()))
            .collect();
        Self {
            manifest: VerifiedManifest {
                manifest,
                raw_bytes,
                sha256: manifest_sha,
            },
            stream_len: artifact_bytes.len() as u64,
            stream_sha,
            chunks,
        }
    }
}

impl DownloadSource for FakeSource {
    type Stream = FakeStream;

    async fn result_manifest(&self, _result_id: &str) -> Result<VerifiedManifest, ClientError> {
        Ok(self.manifest.clone())
    }

    async fn artifact(
        &self,
        artifact_id: &str,
        _max_bytes: u64,
    ) -> Result<Self::Stream, ClientError> {
        assert_eq!(artifact_id, ARTIFACT_ID);
        Ok(FakeStream {
            content_length: self.stream_len,
            sha256: self.stream_sha.clone(),
            chunks: self.chunks.iter().cloned().collect(),
        })
    }
}

#[test]
fn valid_result_id_enforces_exact_prefix_and_lowercase_hex() {
    assert!(valid_result_id("res_0123456789abcdef0123456789abcdef"));
    assert!(!valid_result_id("art_0123456789abcdef0123456789abcdef"));
    assert!(!valid_result_id("res_0123456789ABCDEF0123456789abcdef"));
    assert!(!valid_result_id("res_short"));
    assert!(!valid_result_id("../res_0123456789abcdef0123456789abcdef"));
}

#[test]
fn storage_warnings_surface_reclamation_block_stale_and_unavailable_states() {
    let mut limits = BTreeMap::new();
    limits.insert("result_private_bytes_max".to_owned(), 67_108_864);

    let current = StorageSnapshot {
        api_version: "1.0".to_owned(),
        storage_contract: "rp-0.1".to_owned(),
        usage: StorageUsage {
            retained_input_bytes: Some(0),
            published_output_bytes: Some(64),
            private_staging_bytes: Some(0),
            metadata_bytes: Some(4096),
        },
        limits: limits.clone(),
        measurement: StorageMeasurement {
            status: StorageMeasurementStatus::Current,
            measured_at_ms: Some(100),
        },
    };
    assert!(storage_warnings(&current).is_empty());

    let blocked = StorageSnapshot {
        usage: StorageUsage {
            private_staging_bytes: Some(128),
            ..current.usage.clone()
        },
        measurement: StorageMeasurement {
            status: StorageMeasurementStatus::Stale,
            measured_at_ms: Some(100),
        },
        ..current.clone()
    };
    let blocked_warnings = storage_warnings(&blocked);
    assert_eq!(blocked_warnings.len(), 1);
    assert!(blocked_warnings[0].starts_with("storage_reclamation_blocked:"));

    let stale_zero = StorageSnapshot {
        measurement: StorageMeasurement {
            status: StorageMeasurementStatus::Stale,
            measured_at_ms: Some(100),
        },
        ..current.clone()
    };
    let stale_warnings = storage_warnings(&stale_zero);
    assert_eq!(stale_warnings.len(), 1);
    assert!(stale_warnings[0].starts_with("storage_measurement_stale:"));

    let unavailable = StorageSnapshot {
        usage: StorageUsage {
            retained_input_bytes: None,
            published_output_bytes: None,
            private_staging_bytes: None,
            metadata_bytes: None,
        },
        measurement: StorageMeasurement {
            status: StorageMeasurementStatus::Unavailable,
            measured_at_ms: None,
        },
        ..current
    };
    let unavailable_warnings = storage_warnings(&unavailable);
    assert_eq!(unavailable_warnings.len(), 1);
    assert!(unavailable_warnings[0].starts_with("storage_measurement_unavailable:"));
}

#[test]
fn download_error_maps_to_exit_16_with_job_result_and_completed_files() {
    let error = output_directory_error(
        RESULT_ID,
        JOB_ID,
        ClientOutputError::AlreadyExists,
        vec![SavedFile {
            filename: "mesh.obj".to_owned(),
            artifact_id: Some(ARTIFACT_ID.to_owned()),
            byte_length: 64,
            sha256: "a".repeat(64),
        }],
    )
    .into_command_error();
    assert_eq!(error.exit_code, 16);
    assert_eq!(error.category, "output_already_exists");
    let data = error.context.unwrap().data.unwrap();
    assert_eq!(data["result_id"], RESULT_ID);
    assert_eq!(data["job_id"], JOB_ID);
    assert_eq!(data["complete"], false);
    assert_eq!(data["completed_files"].as_array().unwrap().len(), 1);
}

#[test]
fn download_result_stages_verifies_and_installs_multi_chunk_artifact_and_verbatim_manifest() {
    let payload = vec![b'v'; 70_000];
    let source = FakeSource::for_bytes(&payload);
    let root = TempDir::new().unwrap();
    let dest = root.path().join("saved");

    let report = tokio_runtime()
        .block_on(download_result_with(&source, RESULT_ID, &dest))
        .unwrap();
    assert!(report.complete);
    assert_eq!(report.result_id, RESULT_ID);
    assert_eq!(report.job_id, JOB_ID);
    assert_eq!(report.files.len(), 2);
    assert_eq!(report.files[0].filename, "mesh.obj");
    assert_eq!(report.files[1].filename, "manifest.json");
    assert_eq!(fs::read(dest.join("mesh.obj")).unwrap(), payload);
    assert_eq!(
        fs::read(dest.join("manifest.json")).unwrap(),
        source.manifest.raw_bytes
    );
}

#[test]
fn download_result_refuses_existing_manifest_with_exit_16_and_reports_completed_artifact() {
    let payload = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n";
    let source = FakeSource::for_bytes(payload);
    let root = TempDir::new().unwrap();
    let dest = root.path().join("saved");
    fs::create_dir(&dest).unwrap();
    let sentinel = b"existing client manifest";
    fs::write(dest.join("manifest.json"), sentinel).unwrap();

    let error = tokio_runtime()
        .block_on(download_result_with(&source, RESULT_ID, &dest))
        .unwrap_err();
    assert_eq!(error.exit_code, 16);
    assert_eq!(error.category, "output_already_exists");
    assert_eq!(error.result_id, RESULT_ID);
    assert_eq!(error.job_id.as_deref(), Some(JOB_ID));
    assert_eq!(error.completed_files.len(), 1);
    assert_eq!(error.completed_files[0].filename, "mesh.obj");
    // Sentinel preserved and no staging temp files left behind.
    assert_eq!(fs::read(dest.join("manifest.json")).unwrap(), sentinel);
    assert_eq!(fs::read(dest.join("mesh.obj")).unwrap(), payload);
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
}

#[test]
fn download_result_rejects_corrupt_or_truncated_stream_and_cleans_staging() {
    let payload = b"v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n";
    let mut source = FakeSource::for_bytes(payload);
    // Tamper streamed bytes while keeping declared length/hash from manifest.
    let mut tampered = payload.to_vec();
    tampered[0] = b'X';
    source.chunks = vec![Ok(tampered)];

    let root = TempDir::new().unwrap();
    let dest = root.path().join("saved");
    let error = tokio_runtime()
        .block_on(download_result_with(&source, RESULT_ID, &dest))
        .unwrap_err();
    assert_eq!(error.exit_code, 16);
    assert_eq!(error.category, "integrity_mismatch");
    assert_eq!(error.job_id.as_deref(), Some(JOB_ID));
    assert!(error.completed_files.is_empty());
    assert!(!dest.join("mesh.obj").exists());
    assert!(!dest.join("manifest.json").exists());
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
}
