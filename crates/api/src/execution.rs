//! Execution-aware wire records, separate from the closed queued-only contract.
use crate::{
    JobId, JobRequest, ResolvedJob, StorageStatus, SubmissionDecodeError, SubmissionValue,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
mod native;
pub use native::*;
mod local;
pub use local::*;

pub const JOB_CONTRACT_HEADER: &str = "Dissect3D-Job-Contract";
pub const JOB_CONTRACT: &str = "we-0.1";
pub const EXECUTION_FEATURE: &str = "job_execution.we-0.1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "timeout"
    )]
    pub timeout_ms: Option<u64>,
}

fn timeout<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let number = SubmissionValue::deserialize(d)?;
    let value = match number {
        SubmissionValue::Integer(value) => u64::try_from(value).ok(),
        SubmissionValue::Decimal(value) => exact_deadline_integer(value.as_str()),
        _ => None,
    }
    .ok_or_else(|| serde::de::Error::custom("invalid execution deadline"))?;
    if !(1..=86_400_000).contains(&value) {
        return Err(serde::de::Error::custom("invalid execution deadline"));
    }
    Ok(Some(value))
}

// JSON Schema integers include 1.0 and 1e0. Never round a fractional deadline.
fn exact_deadline_integer(token: &str) -> Option<u64> {
    let (coefficient, exponent) = token.split_once(['e', 'E']).unwrap_or((token, "0"));
    let exponent: i32 = exponent.parse().ok()?;
    let fractional_digits = coefficient.split_once('.').map_or(0, |(_, s)| s.len());
    let mut digits = coefficient.replace('.', "");
    let shift = exponent.checked_sub(i32::try_from(fractional_digits).ok()?)?;
    if shift < 0 {
        let end = digits.len().checked_sub(shift.unsigned_abs() as usize)?;
        if !digits[end..].bytes().all(|b| b == b'0') {
            return None;
        }
        digits.truncate(end);
    } else {
        // A positive deadline is at most eight digits; larger shifts cannot fit.
        if shift > 8 {
            return None;
        }
        digits.extend(std::iter::repeat_n('0', shift as usize));
    }
    digits.parse().ok()
}

/// The legacy portion retains its lossless parameter representation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExecutionJobRequest {
    #[serde(flatten)]
    pub request: JobRequest,
    pub execution: ExecutionPolicy,
}

pub fn decode_execution_request(
    bytes: &[u8],
) -> Result<ExecutionJobRequest, SubmissionDecodeError> {
    let mut value: SubmissionValue = crate::decode_submission_json(bytes, 65_536)?;
    let SubmissionValue::Object(ref mut fields) = value else {
        return Err(SubmissionDecodeError::InvalidRequest);
    };
    let execution = match fields.remove("execution") {
        Some(policy) => decode_execution_json(
            &serde_json::to_vec(&policy).map_err(|_| SubmissionDecodeError::InvalidRequest)?,
            65_536,
        )?,
        None => ExecutionPolicy::default(),
    };
    // Reuse Stage 3's closed shape, role, occurrence and numeric validation.
    let legacy_bytes =
        serde_json::to_vec(&value).map_err(|_| SubmissionDecodeError::InvalidRequest)?;
    let request = crate::decode_job_request(&legacy_bytes)?;
    if request.required_features != [EXECUTION_FEATURE] {
        return Err(SubmissionDecodeError::InvalidRequest);
    }
    Ok(ExecutionJobRequest { request, execution })
}

pub fn encode_execution_request(
    request: &ExecutionJobRequest,
) -> Result<Vec<u8>, SubmissionDecodeError> {
    let bytes = serde_json::to_vec(request).map_err(|_| SubmissionDecodeError::InvalidRequest)?;
    decode_execution_request(&bytes)?;
    Ok(bytes)
}

/// Own the exact POST bytes. Replay never adds fields or normalizes old bodies.
#[derive(Clone, Debug)]
pub struct ExecutionSubmissionBody(Vec<u8>);
impl ExecutionSubmissionBody {
    pub fn fresh(request: &ExecutionJobRequest) -> Result<Self, SubmissionDecodeError> {
        Ok(Self(encode_execution_request(request)?))
    }
    pub fn replay(bytes: Vec<u8>) -> Result<Self, SubmissionDecodeError> {
        if decode_execution_request(&bytes).is_err() {
            let request = crate::decode_job_request(&bytes)?;
            if !request.required_features.is_empty() {
                return Err(SubmissionDecodeError::InvalidRequest);
            }
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionJobState {
    Queued,
    Running,
    CancelRequested,
    Succeeded,
    Partial,
    Failed,
    Canceled,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    Pending,
    Confirmed,
    Fault,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCleanup {
    pub status: CleanupStatus,
    #[serde(deserialize_with = "nullable")]
    pub reason: Option<String>,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProgress {
    pub fraction: f64,
    pub stage: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCancellation {
    pub requested: bool,
    #[serde(deserialize_with = "nullable")]
    pub requested_at_ms: Option<crate::TimestampMs>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOutcome {
    pub code: String,
    pub retryable: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionJobSummary {
    pub api_version: String,
    pub job_contract: String,
    pub job_id: JobId,
    pub acceptance_sequence: i64,
    pub created_at_ms: crate::TimestampMs,
    pub snapshot_revision: u64,
    pub state: ExecutionJobState,
    pub phase: String,
    #[serde(deserialize_with = "nullable")]
    pub progress: Option<ExecutionProgress>,
    pub blockers: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub attempt_id: Option<String>,
    pub cancellation: ExecutionCancellation,
    pub execution_policy: ExecutionPolicy,
    pub cleanup: ExecutionCleanup,
    pub result_ids: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub retry_of: Option<JobId>,
    #[serde(deserialize_with = "nullable")]
    pub outcome: Option<ExecutionOutcome>,
    pub storage_status: StorageStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ExecutionJobSnapshot {
    #[serde(flatten)]
    pub summary: ExecutionJobSummary,
    pub resolved: ResolvedJob,
}

impl<'de> Deserialize<'de> for ExecutionJobSnapshot {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
        let mut value: SubmissionValue =
            crate::decode_submission_json(raw.get().as_bytes(), 262_144)
                .map_err(serde::de::Error::custom)?;
        let SubmissionValue::Object(ref mut fields) = value else {
            return Err(serde::de::Error::custom("expected snapshot"));
        };
        let resolved = fields
            .remove("resolved")
            .ok_or_else(|| serde::de::Error::custom("missing resolution"))?;
        let decode =
            |value: &SubmissionValue| serde_json::to_vec(value).map_err(serde::de::Error::custom);
        Ok(Self {
            resolved: crate::decode_submission_json(&decode(&resolved)?, 262_144)
                .map_err(serde::de::Error::custom)?,
            summary: crate::decode_submission_json(&decode(&value)?, 262_144)
                .map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionJobPage {
    pub api_version: String,
    pub job_contract: String,
    pub items: Vec<ExecutionJobSummary>,
    #[serde(deserialize_with = "nullable")]
    pub next_cursor: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionAcceptance {
    pub api_version: String,
    pub accepted: bool,
    pub job_id: JobId,
    pub replayed: bool,
    pub acceptance_sequence: i64,
    pub snapshot_revision: u64,
    pub resolved: ResolvedJob,
    pub job_contract: String,
    #[serde(deserialize_with = "nullable")]
    pub retry_of: Option<JobId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionControlRequest {
    pub api_version: String,
    pub required_features: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelEffect {
    Requested,
    CanceledBeforeDispatch,
    AlreadyTerminal,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelResponse {
    pub job_snapshot: ExecutionJobSnapshot,
    pub cancel_effect: CancelEffect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCapability {
    pub contract_version: String,
    pub dispatch_enabled: bool,
    pub operations: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    pub required_features: Vec<String>,
}

/// Keeps the older core record unchanged for existing clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionEngineInfo {
    #[serde(flatten)]
    pub core: crate::EngineInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_execution: Option<ExecutionCapability>,
}

/// Schema and required-semantics checks used on every execution response.
pub trait ExecutionRecord: DeserializeOwned {
    fn validate(&self) -> Result<(), crate::ValidationError>;
}
pub fn decode_execution_json<T: ExecutionRecord>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, SubmissionDecodeError> {
    let value: T = crate::decode_submission_json(bytes, maximum)?;
    value
        .validate()
        .map_err(|_| SubmissionDecodeError::InvalidRequest)?;
    Ok(value)
}
fn require(valid: bool) -> Result<(), crate::ValidationError> {
    if valid {
        Ok(())
    } else {
        Err(crate::ValidationError)
    }
}
fn bounded(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max
}
fn execution_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl ExecutionRecord for ExecutionPolicy {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        require(
            self.timeout_ms
                .is_none_or(|v| (1..=86_400_000).contains(&v)),
        )
    }
}
impl ExecutionRecord for ExecutionJobSummary {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        self.execution_policy.validate()?;
        require(
            self.api_version == "1.0"
                && self.job_contract == JOB_CONTRACT
                && self.acceptance_sequence > 0
                && self.snapshot_revision > 0
                && bounded(&self.phase, 128)
                && self.blockers.len() <= 32
                && self.blockers.iter().all(|s| bounded(s, 128))
                && self
                    .attempt_id
                    .as_ref()
                    .is_none_or(|s| execution_id(s, "att_"))
                && self.progress.as_ref().is_none_or(|p| {
                    p.fraction.is_finite()
                        && (0.0..=1.0).contains(&p.fraction)
                        && bounded(&p.stage, 128)
                })
                && self.cleanup.reason.as_ref().is_none_or(|s| bounded(s, 128))
                && self.outcome.as_ref().is_none_or(|o| bounded(&o.code, 128))
                && self.result_ids.len() <= 1
                && self.result_ids.iter().all(|s| execution_id(s, "res_")),
        )
    }
}
impl ExecutionRecord for ExecutionJobSnapshot {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        self.summary.validate()?;
        self.resolved.validate()
    }
}
impl ExecutionRecord for ExecutionAcceptance {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        require(
            self.api_version == "1.0"
                && self.job_contract == JOB_CONTRACT
                && self.accepted
                && self.acceptance_sequence > 0
                && self.snapshot_revision == 1,
        )?;
        self.resolved.validate()
    }
}
impl ExecutionRecord for ExecutionControlRequest {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        require(self.api_version == "1.0" && self.required_features.is_empty())
    }
}
impl ExecutionRecord for CancelResponse {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        self.job_snapshot.validate()
    }
}
impl ExecutionRecord for ExecutionJobPage {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        require(
            self.api_version == "1.0"
                && self.job_contract == JOB_CONTRACT
                && self.items.len() <= 100
                && self.next_cursor.as_ref().is_none_or(|s| bounded(s, 1024)),
        )?;
        for item in &self.items {
            item.validate()?;
        }
        require(
            self.items
                .windows(2)
                .all(|p| p[0].acceptance_sequence < p[1].acceptance_sequence),
        )
    }
}
impl ExecutionRecord for ExecutionCapability {
    fn validate(&self) -> Result<(), crate::ValidationError> {
        require(
            self.contract_version == JOB_CONTRACT
                && self.required_features.len() <= 1
                && self
                    .required_features
                    .iter()
                    .all(|s| s == EXECUTION_FEATURE)
                && !self.limits.is_empty()
                && self.limits.len() <= 128
                && self.operations.len() <= 32
                && self.operations.iter().all(|s| bounded(s, 128))
                && self
                    .operations
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == self.operations.len(),
        )
    }
}
