//! Execution-aware pending records (`record_version: "1.1"`, `job_contract: "we-0.1"`).
//!
//! Covers both `jobs.submit` and `jobs.retry` operations under the shared
//! `CT-CLI-SURFACE §2` profile limits (1 MiB/record, 1,024 records / 64 MiB total).

use super::{MAX_RECORD_BYTES, RecordError, SubmissionRecords};
use dissect3d_api::{
    ClientId, ExecutionAcceptance, ExecutionRecord, IdempotencyKey, InputIdentity, InstallationId,
    JOB_CONTRACT, JobId, SubmissionId, SubmissionValue, decode_execution_request,
    decode_submission_json, encode_execution_request,
};
use dissect3d_platform::{AuthorityLease, PlatformError, RelativePath};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingExecutionRecord {
    pub(crate) record_version: String,
    pub(crate) sub_id: SubmissionId,
    pub(crate) installation_id: InstallationId,
    pub(crate) client_id: ClientId,
    pub(crate) operation: String,
    pub(crate) key: IdempotencyKey,
    pub(crate) job_contract: String,
    pub(crate) request_body_utf8: Option<String>,
    pub(crate) source_job_id: Option<JobId>,
    pub(crate) input_identities: Vec<InputIdentity>,
    pub(crate) receipt: Option<ExecutionAcceptance>,
}

impl PendingExecutionRecord {
    pub(super) fn decode(bytes: &[u8], sub_id: &SubmissionId) -> Result<Self, RecordError> {
        let record: Self =
            decode_submission_json(bytes, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        let original: BTreeMap<String, SubmissionValue> =
            decode_submission_json(bytes, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        let encoded = serde_json::to_vec(&record).map_err(|_| RecordError::Invalid)?;
        let retained: BTreeMap<String, SubmissionValue> =
            decode_submission_json(&encoded, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        if original != retained || record.sub_id != *sub_id {
            return Err(RecordError::Invalid);
        }
        record.validate()?;
        Ok(record)
    }

    pub(super) fn validate(&self) -> Result<(), RecordError> {
        if self.record_version != "1.1" || self.job_contract != JOB_CONTRACT {
            return Err(RecordError::Invalid);
        }
        match self.operation.as_str() {
            "jobs.submit" => self.validate_submit(),
            "jobs.retry" => self.validate_retry(),
            _ => Err(RecordError::Invalid),
        }
    }

    fn validate_submit(&self) -> Result<(), RecordError> {
        if self.source_job_id.is_some() {
            return Err(RecordError::Invalid);
        }
        let body = self
            .request_body_utf8
            .as_deref()
            .ok_or(RecordError::Invalid)?;
        let request =
            decode_execution_request(body.as_bytes()).map_err(|_| RecordError::Invalid)?;
        if encode_execution_request(&request).map_err(|_| RecordError::Invalid)? != body.as_bytes()
        {
            return Err(RecordError::Invalid);
        }
        let expected: BTreeSet<_> = request
            .request
            .inputs
            .values()
            .flatten()
            .map(|input| input.input_id.as_str())
            .collect();
        let mut identities = BTreeMap::new();
        for identity in &self.input_identities {
            if identity.byte_length == 0
                || identity.byte_length > 268_435_456
                || identity.media_type.is_empty()
                || identity.media_type.len() > 128
                || !identity
                    .media_type
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&b))
                || identity.media_type.bytes().filter(|b| *b == b'/').count() != 1
                || identities
                    .insert(identity.input_id.as_str(), identity)
                    .is_some()
            {
                return Err(RecordError::Invalid);
            }
        }
        if expected != identities.keys().copied().collect() {
            return Err(RecordError::Invalid);
        }
        let mut total = 0u64;
        for input in request.request.inputs.values().flatten() {
            total = total
                .checked_add(identities[input.input_id.as_str()].byte_length)
                .ok_or(RecordError::Invalid)?;
            if total > 1_073_741_824 {
                return Err(RecordError::Invalid);
            }
        }
        if let Some(receipt) = &self.receipt {
            if receipt.validate().is_err()
                || receipt.retry_of.is_some()
                || receipt.resolved.inputs.len() != request.request.inputs.len()
                || receipt.resolved.selection.task != request.request.task
            {
                return Err(RecordError::Invalid);
            }
            for (role, inputs) in &request.request.inputs {
                let Some(resolved) = receipt.resolved.inputs.get(role) else {
                    return Err(RecordError::Invalid);
                };
                if resolved.len() != inputs.len()
                    || inputs.iter().zip(resolved).any(|(input, resolved)| {
                        let expected = identities[input.input_id.as_str()];
                        expected.media_type != resolved.media_type
                            || expected.byte_length != resolved.byte_length
                            || expected.sha256 != resolved.sha256
                            || (!receipt.replayed && expected.input_id != resolved.input_id)
                    })
                {
                    return Err(RecordError::Invalid);
                }
            }
        }
        Ok(())
    }

    fn validate_retry(&self) -> Result<(), RecordError> {
        if self.request_body_utf8.is_some() || !self.input_identities.is_empty() {
            return Err(RecordError::Invalid);
        }
        let source = self.source_job_id.as_ref().ok_or(RecordError::Invalid)?;
        if let Some(receipt) = &self.receipt
            && (receipt.validate().is_err()
                || receipt.retry_of.as_ref() != Some(source)
                || receipt.job_id == *source)
        {
            return Err(RecordError::Invalid);
        }
        Ok(())
    }
}

/// Record-level lease for one `1.1` execution pending record.
pub(crate) struct ExecutionRecordLease<'a> {
    profile: &'a crate::connection::Profile,
    sub_id: SubmissionId,
    _lease: AuthorityLease,
}

impl ExecutionRecordLease<'_> {
    pub(crate) fn save_receipt(
        &self,
        record: &PendingExecutionRecord,
        receipt: ExecutionAcceptance,
    ) -> Result<(), RecordError> {
        if self.sub_id != record.sub_id {
            return Err(RecordError::Invalid);
        }
        SubmissionRecords::lock(self.profile)?.save_execution_receipt(record, receipt)
    }
}

impl<'a> SubmissionRecords<'a> {
    pub(crate) fn save_new_execution(
        &self,
        record: &PendingExecutionRecord,
    ) -> Result<(), RecordError> {
        if record.receipt.is_some() {
            return Err(RecordError::Invalid);
        }
        self.write_execution(record, false)
    }

    pub(crate) fn coordinate_execution(
        &self,
        record: &PendingExecutionRecord,
    ) -> Result<ExecutionRecordLease<'a>, RecordError> {
        let super::AnyPendingRecord::Execution(current) = self.load_any(&record.sub_id)? else {
            return Err(RecordError::Invalid);
        };
        if serde_json::to_vec(&current).map_err(|_| RecordError::Invalid)?
            != serde_json::to_vec(record).map_err(|_| RecordError::Invalid)?
        {
            return Err(RecordError::Invalid);
        }
        let path = RelativePath::parse(format!("submission-locks/{}.lock", record.sub_id.as_str()))
            .map_err(|_| RecordError::Invalid)?;
        let lease = AuthorityLease::acquire_at(self.profile.root(), &path).map_err(|error| {
            if error == PlatformError::Busy {
                RecordError::RecordBusy
            } else {
                RecordError::Storage
            }
        })?;
        Ok(ExecutionRecordLease {
            profile: self.profile,
            sub_id: record.sub_id.clone(),
            _lease: lease,
        })
    }

    pub(crate) fn save_execution_receipt(
        &self,
        record: &PendingExecutionRecord,
        receipt: ExecutionAcceptance,
    ) -> Result<(), RecordError> {
        let super::AnyPendingRecord::Execution(mut current) = self.load_any(&record.sub_id)? else {
            return Err(RecordError::Invalid);
        };
        let mut original = record.clone();
        original.receipt = current.receipt.clone();
        if serde_json::to_vec(&current).map_err(|_| RecordError::Invalid)?
            != serde_json::to_vec(&original).map_err(|_| RecordError::Invalid)?
            || current.receipt.as_ref().is_some_and(|old| {
                old.job_id != receipt.job_id
                    || old.resolved != receipt.resolved
                    || old.acceptance_sequence != receipt.acceptance_sequence
                    || old.retry_of != receipt.retry_of
            })
        {
            return Err(RecordError::Invalid);
        }
        current.receipt = Some(receipt);
        self.write_execution(&current, true)
    }

    fn write_execution(
        &self,
        record: &PendingExecutionRecord,
        replacing: bool,
    ) -> Result<(), RecordError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record).map_err(|_| RecordError::Invalid)?;
        self.write_raw(&record.sub_id, &bytes, replacing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Profile;
    use dissect3d_api::{ExecutionJobSnapshot, decode_execution_json};

    fn retry_record() -> PendingExecutionRecord {
        PendingExecutionRecord {
            record_version: "1.1".into(),
            sub_id: SubmissionId::parse("sub_11111111111111111111111111111111").expect("sub"),
            installation_id: InstallationId::parse("ins_11111111111111111111111111111111")
                .expect("ins"),
            client_id: ClientId::parse("cli_11111111111111111111111111111111").expect("cli"),
            operation: "jobs.retry".into(),
            key: IdempotencyKey::parse("retry-key-1").expect("key"),
            job_contract: JOB_CONTRACT.into(),
            request_body_utf8: None,
            source_job_id: Some(JobId::parse("job_00000000000000000000000000000001").expect("job")),
            input_identities: Vec::new(),
            receipt: None,
        }
    }

    fn retry_acceptance() -> ExecutionAcceptance {
        let snap: ExecutionJobSnapshot = decode_execution_json(
            include_bytes!("../../../api/tests/fixtures/execution-snapshot.json"),
            262_144,
        )
        .expect("fixture snapshot");
        ExecutionAcceptance {
            api_version: "1.0".into(),
            accepted: true,
            job_id: JobId::parse("job_00000000000000000000000000000002").expect("job2"),
            replayed: false,
            acceptance_sequence: 1,
            snapshot_revision: 1,
            resolved: snap.resolved,
            job_contract: JOB_CONTRACT.into(),
            retry_of: Some(JobId::parse("job_00000000000000000000000000000001").expect("job1")),
        }
    }

    #[test]
    fn execution_record_roundtrips_through_load_any_and_saves_receipt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile = Profile::open(&dir.path().join("profile.json")).expect("profile");
        let record = retry_record();
        let lease = {
            let records = SubmissionRecords::lock(&profile).expect("lock");
            records.save_new_execution(&record).expect("save new");
            match records.load_any(&record.sub_id).expect("load_any") {
                super::super::AnyPendingRecord::Execution(loaded) => {
                    assert_eq!(loaded.operation, "jobs.retry");
                    assert_eq!(loaded.key, record.key);
                }
                super::super::AnyPendingRecord::Stage3(_) => panic!("expected 1.1 record"),
            }
            records.coordinate_execution(&record).expect("coordinate")
        };
        let acceptance = retry_acceptance();
        lease
            .save_receipt(&record, acceptance.clone())
            .expect("save receipt");
        let records = SubmissionRecords::lock(&profile).expect("relock");
        match records.load_any(&record.sub_id).expect("reload") {
            super::super::AnyPendingRecord::Execution(loaded) => {
                assert_eq!(
                    loaded.receipt.as_ref().map(|r| &r.job_id),
                    Some(&acceptance.job_id)
                );
            }
            super::super::AnyPendingRecord::Stage3(_) => panic!("expected 1.1 record"),
        }
    }
}
