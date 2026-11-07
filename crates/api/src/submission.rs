//! Shared durable-submission wire records. The client remains optional and
//! transport-neutral types live here so the engine never depends on reqwest.

mod json;
pub(crate) mod validation;

pub use json::{
    DecimalToken, SubmissionDecodeError, SubmissionValue, decode_job_request,
    decode_submission_json, encode_job_request,
};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

macro_rules! submission_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, crate::ValidationError> {
                let value = value.into();
                let Some(suffix) = value.strip_prefix($prefix) else {
                    return Err(crate::ValidationError);
                };
                if suffix.len() != 32
                    || !suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(crate::ValidationError);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

submission_id!(InputId, "inp_");
submission_id!(JobId, "job_");
submission_id!(SubmissionId, "sub_");

/// Lowercase hexadecimal SHA-256 content identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    pub fn parse(value: impl Into<String>) -> Result<Self, crate::ValidationError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(crate::ValidationError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// One submitted task key, retained without applying discovery's narrower grammar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmittedTask {
    pub id: String,
    pub version: String,
}

/// Engine-issued identity reference in a closed job request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputRef {
    pub input_id: InputId,
}

/// Closed request submitted to the engine after local files have been captured.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub api_version: String,
    pub support_ref: String,
    pub task: SubmittedTask,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    pub inputs: BTreeMap<String, Vec<InputRef>>,
    pub parameters: BTreeMap<String, SubmissionValue>,
    pub required_features: Vec<String>,
    pub evaluation_consent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputIdentity {
    pub input_id: InputId,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputReceipt {
    pub api_version: String,
    #[serde(flatten)]
    pub identity: InputIdentity,
    pub complete: bool,
    pub completed_at_ms: crate::TimestampMs,
    pub expires_at_ms: crate::TimestampMs,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchSnapshot {
    pub id: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSnapshot {
    pub upstream_repository: String,
    pub upstream_revision: String,
    pub executed_repository: String,
    pub executed_revision: String,
    pub patches: Vec<PatchSnapshot>,
    pub build_provenance: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSnapshot {
    pub id: String,
    pub revision: String,
    pub sha256: String,
    pub interface_version: String,
    pub required_worker_features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetSnapshot {
    pub id: String,
    pub kind: String,
    pub source: String,
    pub revision: String,
    pub sha256: String,
    pub byte_length: u64,
    pub prerequisites: Vec<String>,
    pub rights_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaSnapshot {
    pub id: String,
    pub version: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionSnapshot {
    pub support_id: String,
    pub support_ref: String,
    pub support_sha256: String,
    pub code: CodeSnapshot,
    pub adapter: AdapterSnapshot,
    pub assets: Vec<AssetSnapshot>,
    pub task_binding_id: String,
    pub task: SubmittedTask,
    pub schemas: Vec<SchemaSnapshot>,
    pub runtime_id: String,
    pub runtime_ref: String,
    pub runtime_sha256: String,
    pub variant: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedReadiness {
    pub check_id: String,
    pub fingerprint: ContentDigest,
    pub runtime_realization: String,
    pub integrity_sha256: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationEvidence {
    pub validator_id: String,
    pub revision: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedJob {
    pub selection: SelectionSnapshot,
    pub effective_parameters: BTreeMap<String, SubmissionValue>,
    pub inputs: BTreeMap<String, Vec<InputIdentity>>,
    pub readiness: PreparedReadiness,
    pub validation: Vec<ValidationEvidence>,
    pub evidence_scope: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AcceptanceReceipt {
    pub api_version: String,
    pub accepted: bool,
    pub job_id: JobId,
    pub replayed: bool,
    pub acceptance_sequence: i64,
    pub snapshot_revision: u64,
    pub resolved: ResolvedJob,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSummary {
    pub job_id: JobId,
    pub acceptance_sequence: i64,
    pub snapshot_revision: u64,
    pub state: JobState,
    pub blockers: Vec<String>,
    pub created_at_ms: crate::TimestampMs,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub api_version: String,
    #[serde(flatten)]
    pub summary: JobSummary,
    pub resolved: ResolvedJob,
    pub storage_status: StorageStatus,
    #[serde(default)]
    pub attempt_id: Option<String>,
    #[serde(default)]
    pub result_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageStatus {
    Verified,
    StorageIntegrityFault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobPage {
    pub api_version: String,
    pub items: Vec<JobSummary>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobsQuery {
    pub limit: Option<u8>,
    pub cursor: Option<String>,
}
