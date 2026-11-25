//! Closed read records. These types do not activate routes or publication.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultAvailability {
    Available,
    Unavailable,
    IntegrityFault,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultSummary {
    pub result_id: String,
    pub job_id: JobId,
    pub attempt_id: String,
    pub published_at_ms: u64,
    pub availability: ResultAvailability,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResultsQuery {
    pub limit: Option<u8>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPage {
    pub api_version: String,
    pub result_contract: String,
    pub items: Vec<ResultSummary>,
    #[serde(deserialize_with = "required_nullable")]
    pub next_cursor: Option<String>,
    pub truncated: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPublicationCapability {
    pub contract_version: String,
    pub operations: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    pub required_features: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageUsage {
    #[serde(deserialize_with = "required_nullable")]
    pub retained_input_bytes: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub published_output_bytes: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub private_staging_bytes: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    pub metadata_bytes: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMeasurementStatus {
    Current,
    Stale,
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageMeasurement {
    pub status: StorageMeasurementStatus,
    #[serde(deserialize_with = "required_nullable")]
    pub measured_at_ms: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSnapshot {
    pub api_version: String,
    pub storage_contract: String,
    pub usage: StorageUsage,
    pub limits: BTreeMap<String, u64>,
    pub measurement: StorageMeasurement,
}
fn limits_valid(limits: &BTreeMap<String, u64>) -> bool {
    !limits.is_empty() && limits.len() <= 128
}
pub fn decode_result_page(bytes: &[u8]) -> Result<ResultPage, SubmissionDecodeError> {
    let page: ResultPage = crate::decode_submission_json(bytes, 262_144)?;
    if page.api_version != "1.0"
        || page.result_contract != "rp-0.1"
        || page.items.len() > 100
        || page.truncated != page.next_cursor.is_some()
        || (page.truncated && page.items.is_empty())
        || page.next_cursor.as_ref().is_some_and(|s| !bounded(s, 1024))
    {
        return Err(invalid());
    }
    let mut results = BTreeSet::new();
    let mut jobs = BTreeSet::new();
    for item in &page.items {
        if !id(&item.result_id, "res_")
            || !id(&item.attempt_id, "att_")
            || !results.insert(&item.result_id)
            || !jobs.insert(item.job_id.as_str())
        {
            return Err(invalid());
        }
    }
    // Acceptance ordering and publication high-water membership require Store
    // evidence; publication timestamps cannot establish either property.
    Ok(page)
}
pub fn decode_result_publication_capability(
    bytes: &[u8],
) -> Result<ResultPublicationCapability, SubmissionDecodeError> {
    let value: ResultPublicationCapability = crate::decode_submission_json(bytes, 262_144)?;
    if value.contract_version != "rp-0.1"
        || !limits_valid(&value.limits)
        || value.operations.len() > 32
        || value.operations.iter().any(|s| !bounded(s, 128))
        || value.required_features.len() > 32
        || value.required_features.iter().any(|s| s != RESULT_FEATURE)
    {
        return Err(invalid());
    }
    Ok(value)
}
pub fn decode_storage_snapshot(bytes: &[u8]) -> Result<StorageSnapshot, SubmissionDecodeError> {
    let value: StorageSnapshot = crate::decode_submission_json(bytes, 262_144)?;
    if value.api_version != "1.0"
        || value.storage_contract != "rp-0.1"
        || !limits_valid(&value.limits)
    {
        return Err(invalid());
    }
    match value.measurement.status {
        StorageMeasurementStatus::Unavailable => {
            if [
                value.usage.retained_input_bytes,
                value.usage.published_output_bytes,
                value.usage.private_staging_bytes,
                value.usage.metadata_bytes,
            ]
            .iter()
            .any(Option::is_some)
            {
                return Err(invalid());
            }
        }
        StorageMeasurementStatus::Current | StorageMeasurementStatus::Stale => {
            if value.measurement.measured_at_ms.is_none() {
                return Err(invalid());
            }
        }
    }
    Ok(value)
}
