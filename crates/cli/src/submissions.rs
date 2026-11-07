//! Protected client recovery metadata; the engine remains the job authority.

use crate::connection::Profile;
use dissect3d_api::{
    AcceptanceReceipt, ClientId, IdempotencyKey, InputIdentity, InstallationId, SubmissionId,
    SubmissionValue, decode_job_request, decode_submission_json, encode_job_request,
};
use dissect3d_platform::{AuthorityLease, PlatformError, RelativePath};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_RECORD_BYTES: usize = 1_048_576;
const MAX_RECORDS: usize = 1024;
const MAX_PROFILE_BYTES: u64 = 67_108_864;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    Missing,
    Invalid,
    Storage,
    Capacity,
    Busy,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingSubmission {
    pub(crate) record_version: String,
    pub(crate) sub_id: SubmissionId,
    pub(crate) installation_id: InstallationId,
    pub(crate) client_id: ClientId,
    pub(crate) operation: String,
    pub(crate) key: IdempotencyKey,
    pub(crate) request_body_utf8: String,
    pub(crate) input_identities: Vec<InputIdentity>,
    pub(crate) receipt: Option<AcceptanceReceipt>,
}

impl PendingSubmission {
    fn decode(bytes: &[u8], sub_id: &SubmissionId) -> Result<Self, RecordError> {
        let record: Self =
            decode_submission_json(bytes, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        // Closed local records must not silently drop nested fields or invent
        // an omitted nullable receipt. Compare lossless trees, not f64 values.
        let original: BTreeMap<String, SubmissionValue> =
            decode_submission_json(bytes, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        let encoded = serde_json::to_vec(&record).map_err(|_| RecordError::Invalid)?;
        let retained: BTreeMap<String, SubmissionValue> =
            decode_submission_json(&encoded, MAX_RECORD_BYTES).map_err(|_| RecordError::Invalid)?;
        if original != retained {
            return Err(RecordError::Invalid);
        }
        if record.sub_id != *sub_id {
            return Err(RecordError::Invalid);
        }
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), RecordError> {
        if self.record_version != "1.0" || self.operation != "jobs.submit" {
            return Err(RecordError::Invalid);
        }
        let request = decode_job_request(self.request_body_utf8.as_bytes())
            .map_err(|_| RecordError::Invalid)?;
        if encode_job_request(&request).map_err(|_| RecordError::Invalid)?
            != self.request_body_utf8.as_bytes()
        {
            return Err(RecordError::Invalid);
        }
        let expected: BTreeSet<_> = request
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
        for input in request.inputs.values().flatten() {
            total = total
                .checked_add(identities[input.input_id.as_str()].byte_length)
                .ok_or(RecordError::Invalid)?;
            if total > 1_073_741_824 {
                return Err(RecordError::Invalid);
            }
        }
        if let Some(receipt) = &self.receipt {
            if receipt.validate().is_err()
                || receipt.resolved.inputs.len() != request.inputs.len()
                || receipt.resolved.selection.task != request.task
            {
                return Err(RecordError::Invalid);
            }
            for (role, inputs) in &request.inputs {
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
}

/// Holding this value serializes scan/check/write across CLI processes.
pub(crate) struct SubmissionRecords<'a> {
    profile: &'a Profile,
    _lease: AuthorityLease,
}

impl<'a> SubmissionRecords<'a> {
    pub(crate) fn open_existing(config: &Path) -> Result<Profile, RecordError> {
        // Distinguish absence before acquiring a lock: recovery must not create
        // a root merely to discover that its record is missing.
        let mut path = config.as_os_str().to_os_string();
        path.push(".state");
        match std::fs::symlink_metadata(Path::new(&path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RecordError::Missing);
            }
            Err(_) => return Err(RecordError::Storage),
            Ok(_) => {}
        }
        Profile::open_existing(config).map_err(|_| RecordError::Storage)
    }

    pub(crate) fn lock(profile: &'a Profile) -> Result<Self, RecordError> {
        let lease = profile.lock_control().map_err(|error| {
            if error == crate::connection::ConnectionError::ProfileBusy {
                RecordError::Busy
            } else {
                RecordError::Storage
            }
        })?;
        Ok(Self {
            profile,
            _lease: lease,
        })
    }

    pub(crate) fn load(&self, sub_id: &SubmissionId) -> Result<PendingSubmission, RecordError> {
        let bytes = self
            .profile
            .root()
            .read_file(&record_path(sub_id), MAX_RECORD_BYTES)
            .map_err(|error| {
                if error == PlatformError::NotFound {
                    RecordError::Missing
                } else {
                    RecordError::Storage
                }
            })?;
        PendingSubmission::decode(&bytes, sub_id)
    }

    fn scan(&self) -> Result<(Vec<SubmissionId>, u64), RecordError> {
        let root = self.profile.root();
        let directory = RelativePath::parse("submissions").unwrap();
        let mut scan = match root.scan_owned_inputs(&directory) {
            Ok(scan) => scan,
            Err(PlatformError::NotFound) => return Ok((Vec::new(), 0)),
            Err(_) => return Err(RecordError::Storage),
        };
        let mut ids = Vec::new();
        let mut bytes = 0u64;
        let mut entries = 0usize;
        let mut removed_orphans = 0usize;
        loop {
            let batch = scan.next_batch(64).map_err(|_| RecordError::Storage)?;
            if batch.rejected_entries != 0 {
                return Err(RecordError::Storage);
            }
            for path in batch.entries {
                let name = path
                    .as_str()
                    .strip_prefix("submissions/")
                    .ok_or(RecordError::Invalid)?;
                if is_atomic_temporary(name) {
                    // Bound native deletion/barrier work per command too. A
                    // retry resumes from the names durably removed so far.
                    if removed_orphans == MAX_RECORDS {
                        return Err(RecordError::Busy);
                    }
                    // The profile lease excludes live cooperating writers. Only
                    // exact writer names and private, unaliased regular files
                    // are removable; release their charge after the barrier.
                    root.file_metadata(&path)
                        .map_err(|_| RecordError::Storage)?;
                    root.remove_durable(&path)
                        .map_err(|_| RecordError::Storage)?;
                    removed_orphans += 1;
                    continue;
                }
                entries += 1;
                if entries > MAX_RECORDS {
                    return Err(RecordError::Capacity);
                }
                if let Some(id) = name.strip_suffix(".json") {
                    ids.push(SubmissionId::parse(id).map_err(|_| RecordError::Invalid)?);
                } else {
                    return Err(RecordError::Invalid);
                }
                let metadata = root
                    .file_metadata(&path)
                    .map_err(|_| RecordError::Storage)?;
                if metadata.length > MAX_RECORD_BYTES as u64 {
                    return Err(RecordError::Capacity);
                }
                bytes = bytes
                    .checked_add(metadata.length)
                    .ok_or(RecordError::Capacity)?;
                if bytes > MAX_PROFILE_BYTES {
                    return Err(RecordError::Capacity);
                }
            }
            if batch.exhausted {
                break;
            }
        }
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok((ids, bytes))
    }

    pub(crate) fn save_new(&self, record: &PendingSubmission) -> Result<(), RecordError> {
        if record.receipt.is_some() {
            return Err(RecordError::Invalid);
        }
        self.write(record, false)
    }

    pub(crate) fn save_receipt(
        &self,
        record: &PendingSubmission,
        receipt: AcceptanceReceipt,
    ) -> Result<(), RecordError> {
        let mut current = self.load(&record.sub_id)?;
        let mut original = record.clone();
        original.receipt = current.receipt.clone();
        if serde_json::to_vec(&current).map_err(|_| RecordError::Invalid)?
            != serde_json::to_vec(&original).map_err(|_| RecordError::Invalid)?
            || current.receipt.as_ref().is_some_and(|old| {
                old.job_id != receipt.job_id
                    || old.resolved != receipt.resolved
                    || old.acceptance_sequence != receipt.acceptance_sequence
            })
        {
            return Err(RecordError::Invalid);
        }
        current.receipt = Some(receipt);
        self.write(&current, true)
    }

    fn write(&self, record: &PendingSubmission, replacing: bool) -> Result<(), RecordError> {
        record.validate()?;
        let bytes = serde_json::to_vec(record).map_err(|_| RecordError::Invalid)?;
        let (ids, existing_bytes) = self.scan()?;
        if ids.contains(&record.sub_id) != replacing {
            return Err(RecordError::Invalid);
        }
        check_capacity(ids.len(), existing_bytes, bytes.len(), replacing)?;
        self.profile
            .root()
            .write_recovery_record(&record_path(&record.sub_id), &bytes)
            .map_err(|_| RecordError::Storage)
    }
}

fn is_atomic_temporary(name: &str) -> bool {
    // Matches platform's Unix write_atomic: positive pid and u64 counter,
    // formatted as canonical decimal integers, with no trailing components.
    let Some((pid, counter)) = name
        .strip_prefix(".d3d-tmp-")
        .and_then(|s| s.split_once('-'))
    else {
        return false;
    };
    pid.parse::<i32>()
        .is_ok_and(|n| n > 0 && n.to_string() == pid)
        && counter
            .parse::<u64>()
            .is_ok_and(|n| n.to_string() == counter)
}

fn record_path(id: &SubmissionId) -> RelativePath {
    RelativePath::parse(format!("submissions/{}.json", id.as_str())).unwrap()
}

fn check_capacity(
    records: usize,
    bytes: u64,
    new_bytes: usize,
    replacing: bool,
) -> Result<(), RecordError> {
    if new_bytes > MAX_RECORD_BYTES
        || records > MAX_RECORDS
        || (!replacing && records == MAX_RECORDS)
        || bytes
            .checked_add(new_bytes as u64)
            .is_none_or(|peak| peak > MAX_PROFILE_BYTES)
    {
        return Err(RecordError::Capacity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dissect3d_api::{ContentDigest, InputId};

    #[test]
    fn orphan_names_match_only_canonical_atomic_writer_names() {
        for name in [".d3d-tmp-1-0", ".d3d-tmp-2147483647-18446744073709551615"] {
            assert!(is_atomic_temporary(name), "{name}");
        }
        for name in [
            ".d3d-tmp-0-0",
            ".d3d-tmp-01-0",
            ".d3d-tmp-1-00",
            ".d3d-tmp-+1-0",
            ".d3d-tmp-1-2-extra",
            ".d3d-tmp-1-18446744073709551616",
            ".d3d-tmp-2147483648-0",
        ] {
            assert!(!is_atomic_temporary(name), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn orphan_cleanup_preserves_unknown_names_and_rejects_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
        let records = SubmissionRecords::lock(&profile).unwrap();
        let unknown = RelativePath::parse("submissions/.d3d-tmp-1-0-extra").unwrap();
        profile.root().write_atomic(&unknown, b"keep").unwrap();
        assert_eq!(records.scan().err(), Some(RecordError::Invalid));
        assert_eq!(profile.root().read_file(&unknown, 4).unwrap(), b"keep");
        profile.root().remove_file(&unknown).unwrap();
        let target = RelativePath::parse("target").unwrap();
        profile.root().write_atomic(&target, b"keep").unwrap();
        let link = profile.root().path().join("submissions/.d3d-tmp-1-0");
        symlink(profile.root().path().join("target"), &link).unwrap();
        assert_eq!(records.scan().err(), Some(RecordError::Storage));
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(profile.root().read_file(&target, 4).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn orphan_cleanup_is_bounded_and_retries_make_progress() {
        let temp = tempfile::tempdir().unwrap();
        let profile = Profile::open(&temp.path().join("profile.json")).unwrap();
        let records = SubmissionRecords::lock(&profile).unwrap();
        for counter in 0..=MAX_RECORDS {
            profile
                .root()
                .write_atomic(
                    &RelativePath::parse(format!("submissions/.d3d-tmp-1-{counter}")).unwrap(),
                    b"x",
                )
                .unwrap();
        }
        assert_eq!(records.scan().err(), Some(RecordError::Busy));
        assert_eq!(
            std::fs::read_dir(profile.root().path().join("submissions"))
                .unwrap()
                .count(),
            1
        );
        records.save_new(&pending()).unwrap();
        assert_eq!(records.scan().unwrap().0, vec![pending().sub_id]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_atomic_record_helper() {
        let Some(config) = std::env::var_os("D3_RECORD_CRASH_CONFIG") else {
            return;
        };
        let profile = Profile::open(Path::new(&config)).unwrap();
        let _records = SubmissionRecords::lock(&profile).unwrap();
        profile
            .root()
            .write_recovery_record(
                &RelativePath::parse("submissions/unpublished.json").unwrap(),
                &vec![b'x'; MAX_RECORD_BYTES],
            )
            .unwrap();
        panic!("the parent must kill the stopped writer before rename");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn killed_atomic_writers_release_orphan_quota_on_recovery() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("profile.json");
        let profile = Profile::open(&config).unwrap();
        // Preserve an unresolved record while accumulating more than 64 MiB
        // of actual interrupted write_atomic siblings.
        let record = pending();
        SubmissionRecords::lock(&profile)
            .unwrap()
            .save_new(&record)
            .unwrap();
        let library = temp.path().join("stop-atomic.so");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stop_atomic_record.c");
        assert!(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
                .arg(source)
                .arg("-o")
                .arg(&library)
                .arg("-ldl")
                .status()
                .unwrap()
                .success()
        );
        for _ in 0..65 {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "submissions::tests::interrupted_atomic_record_helper",
                    "--nocapture",
                ])
                .env("D3_RECORD_CRASH_CONFIG", &config)
                .env("LD_PRELOAD", &library)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let stopped = loop {
                let status = std::fs::read_to_string(format!("/proc/{}/status", child.id()))
                    .unwrap_or_default();
                if status
                    .lines()
                    .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
                {
                    break true;
                }
                if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            // Always reap our helper, including an assertion/timeout failure.
            let _ = child.kill();
            let status = child.wait().unwrap();
            assert!(
                stopped && !status.success(),
                "writer did not stop before rename"
            );
        }
        let directory = profile.root().path().join("submissions");
        let orphan_bytes: u64 = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                if is_atomic_temporary(entry.file_name().to_str().unwrap()) {
                    entry.metadata().unwrap().len()
                } else {
                    0
                }
            })
            .sum();
        assert!(orphan_bytes > MAX_PROFILE_BYTES);
        let records = SubmissionRecords::lock(&profile).unwrap();
        let mut next = pending();
        next.sub_id = SubmissionId::parse(format!("sub_{}", "4".repeat(32))).unwrap();
        records.save_new(&next).unwrap();
        assert_eq!(
            records.load(&record.sub_id).unwrap().request_body_utf8,
            record.request_body_utf8
        );
        let mut receipt: AcceptanceReceipt = decode_submission_json(
            include_bytes!("../tests/fixtures/illustrative-acceptance.json"),
            262_144,
        )
        .unwrap();
        receipt.resolved.selection.task = decode_job_request(record.request_body_utf8.as_bytes())
            .unwrap()
            .task;
        receipt.resolved.inputs = [("mesh".into(), record.input_identities.clone())].into();
        records.save_receipt(&record, receipt).unwrap();
        assert!(records.load(&record.sub_id).unwrap().receipt.is_some());
        assert_eq!(std::fs::read_dir(directory).unwrap().count(), 2);
    }

    fn pending() -> PendingSubmission {
        let body = format!(
            r#"{{"api_version":"1.0","support_ref":"fixture@r1","task":{{"id":"mesh.copy","version":"1.0"}},"inputs":{{"mesh":[{{"input_id":"inp_{}"}}]}},"parameters":{{"scale":1.00000000000000000000001}},"required_features":[],"evaluation_consent":false}}"#,
            "0".repeat(32)
        );
        PendingSubmission {
            record_version: "1.0".into(),
            sub_id: SubmissionId::parse(format!("sub_{}", "1".repeat(32))).unwrap(),
            installation_id: InstallationId::parse(format!("ins_{}", "2".repeat(32))).unwrap(),
            client_id: ClientId::parse(format!("cli_{}", "3".repeat(32))).unwrap(),
            operation: "jobs.submit".into(),
            key: IdempotencyKey::parse("stable-key").unwrap(),
            request_body_utf8: body,
            input_identities: vec![InputIdentity {
                input_id: InputId::parse(format!("inp_{}", "0".repeat(32))).unwrap(),
                media_type: "application/octet-stream".into(),
                byte_length: 4,
                sha256: ContentDigest::parse("a".repeat(64)).unwrap(),
            }],
            receipt: None,
        }
    }

    #[test]
    fn record_validation_binds_ids_body_and_complete_input_identity_without_float_rounding() {
        let record = pending();
        let bytes = serde_json::to_vec(&record).unwrap();
        let decoded = PendingSubmission::decode(&bytes, &record.sub_id).unwrap();
        assert_eq!(decoded.request_body_utf8, record.request_body_utf8);
        assert!(
            decoded
                .request_body_utf8
                .contains("1.00000000000000000000001")
        );
        assert!(
            PendingSubmission::decode(
                &bytes,
                &SubmissionId::parse(format!("sub_{}", "9".repeat(32))).unwrap()
            )
            .is_err()
        );
        let mut bad = pending();
        bad.input_identities.clear();
        assert!(bad.validate().is_err());
        let mut bad = pending();
        bad.input_identities.push(bad.input_identities[0].clone());
        assert!(bad.validate().is_err());
        let mut bad = pending();
        bad.operation = "engine.stop".into();
        assert!(bad.validate().is_err());
        let mut bad = pending();
        bad.input_identities[0].byte_length = 0;
        assert!(bad.validate().is_err());
        let mut bad = pending();
        bad.record_version = "2.0".into();
        assert!(bad.validate().is_err());
        let mut bad = pending();
        bad.request_body_utf8.push('\n');
        assert!(
            bad.validate().is_err(),
            "recovery must reproduce the exact encoder output"
        );
        let text = String::from_utf8(bytes).unwrap();
        let extra_identity = text.replace(
            "\"byte_length\":4",
            "\"byte_length\":4,\"path\":\"private-source.obj\"",
        );
        assert!(PendingSubmission::decode(extra_identity.as_bytes(), &record.sub_id).is_err());
        let absent_receipt = text.replace(",\"receipt\":null", "");
        assert!(PendingSubmission::decode(absent_receipt.as_bytes(), &record.sub_id).is_err());
    }

    #[test]
    fn reading_absent_profile_never_creates_recovery_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profile.json");
        assert!(matches!(
            SubmissionRecords::open_existing(&path),
            Err(RecordError::Missing)
        ));
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn capacity_accounts_replacement_peak_and_never_discards_existing_records() {
        assert!(check_capacity(1023, 63 * 1024 * 1024, 1024 * 1024, false).is_ok());
        assert!(check_capacity(1024, 0, 1, false).is_err());
        assert!(check_capacity(1024, 0, 1, true).is_ok());
        assert!(check_capacity(1, 64 * 1024 * 1024, 1, true).is_err());
        assert!(check_capacity(0, 0, 1024 * 1024 + 1, false).is_err());
        assert!(check_capacity(1, u64::MAX, 1, false).is_err());
    }

    #[test]
    fn local_receipt_validation_rejects_invalid_resolution_and_allows_equivalent_replay() {
        let mut record = pending();
        let mut receipt: AcceptanceReceipt = decode_submission_json(
            include_bytes!("../tests/fixtures/illustrative-acceptance.json"),
            262_144,
        )
        .unwrap();
        receipt.resolved.selection.task = decode_job_request(record.request_body_utf8.as_bytes())
            .unwrap()
            .task;
        receipt.resolved.inputs = [("mesh".into(), record.input_identities.clone())].into();
        record.receipt = Some(receipt.clone());
        assert!(record.validate().is_ok());
        let mut invalid = receipt.clone();
        invalid.resolved.validation.clear();
        record.receipt = Some(invalid);
        assert!(record.validate().is_err());
        let mut invalid = receipt.clone();
        invalid.resolved.validation[0].status = "failed".into();
        record.receipt = Some(invalid);
        assert!(record.validate().is_err());
        let mut invalid = receipt.clone();
        invalid.resolved.readiness.check_id.clear();
        record.receipt = Some(invalid);
        assert!(record.validate().is_err());
        let mut invalid = receipt.clone();
        invalid.resolved.selection.runtime_sha256 = "invalid".into();
        record.receipt = Some(invalid);
        assert!(record.validate().is_err());
        receipt.replayed = true;
        receipt.resolved.inputs.get_mut("mesh").unwrap()[0].input_id =
            InputId::parse(format!("inp_{}", "9".repeat(32))).unwrap();
        record.receipt = Some(receipt.clone());
        assert!(
            record.validate().is_ok(),
            "replacement-ID replay binds verified content"
        );
        receipt.replayed = false;
        record.receipt = Some(receipt);
        assert!(
            record.validate().is_err(),
            "a fresh acceptance must retain the uploaded IDs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_records_are_locked_immutable_bounded_and_reopen_without_creating() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("profile.json");
        let profile = Profile::open(&config).unwrap();
        let records = SubmissionRecords::lock(&profile).unwrap();
        let record = pending();
        records.save_new(&record).unwrap();
        assert!(SubmissionRecords::lock(&profile).is_err());
        assert_eq!(
            records.load(&record.sub_id).unwrap().request_body_utf8,
            record.request_body_utf8
        );
        assert!(
            records.save_new(&record).is_err(),
            "must never overwrite an unresolved record"
        );
        let path = profile
            .root()
            .path()
            .join(format!("submissions/{}.json", record.sub_id.as_str()));
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert_eq!(records.scan().unwrap().0, vec![record.sub_id.clone()]);
        let unsafe_name = profile.root().path().join("submissions/unsafe");
        symlink(&path, &unsafe_name).unwrap();
        assert!(records.scan().is_err());
        assert!(records.save_new(&pending()).is_err());
        std::fs::remove_file(unsafe_name).unwrap();
        drop(records);
        drop(profile);
        let profile = SubmissionRecords::open_existing(&config).unwrap();
        let records = SubmissionRecords::lock(&profile).unwrap();
        assert_eq!(
            records.load(&record.sub_id).unwrap().request_body_utf8,
            record.request_body_utf8
        );
    }
}
