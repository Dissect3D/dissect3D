//! Bounded fresh-request admission facts retained through atomic acceptance.

#[cfg(all(test, feature = "test-support"))]
use super::equivalence::CanonicalizationVersion;
use super::equivalence::{CanonicalSubmission, VerifiedInputMap};
use super::obj::{
    ObjError, ObjSummary, VALIDATION_WALL_BUDGET, ValidationPermit, check_deadline, validate_obj_in,
};
use super::schema::{
    resolve_parameters, schema_for_binding, validate_fixture_inputs, validate_known_schemas,
};
use crate::store::inputs::PinnedInputSet;
#[cfg(feature = "test-support")]
use crate::submission_fixture::PreparedReadiness as FixtureReadiness;
use crate::support::{Catalog, ResolvedSelection, Selection};
use dissect3d_api::{
    AcceptanceReceipt, AdapterSnapshot, AssetSnapshot, CodeSnapshot, InputIdentity, JobId,
    JobRequest, JobSnapshot, JobState, JobSummary, PatchSnapshot, PreparedReadiness, ResolvedJob,
    SchemaSnapshot, SelectionSnapshot, StorageStatus, SubmittedTask, TimestampMs,
    ValidationEvidence,
};
use serde::Serialize;
#[cfg(all(test, feature = "test-support"))]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

const REQUEST_BYTES_MAX: usize = 65_536;
const CANONICAL_BYTES_MAX: usize = 262_144;
const METADATA_BYTES_MAX: usize = 262_144;
const BINDING_BYTES_MAX: usize = 16_384;
const INPUT_BYTES_MAX: u64 = 268_435_456;
const JOB_INPUT_BYTES_MAX: u64 = 1_073_741_824;
const ROLES_MAX: usize = 16;
const INPUT_OCCURRENCES_MAX: usize = 64;
const REQUIRED_FEATURES_MAX: usize = 32;
const RESPONSE_BYTES_MAX: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionError {
    InvalidRequest,
    UnsupportedSelection,
    UnsupportedParameter,
    RequiredFeatureUnsupported,
    InvalidInput,
    InputUnavailable,
    NotPrepared,
    StorageIntegrityFault,
    CapacityExceeded,
}

pub(crate) struct AdmissionCandidate {
    pub(crate) canonical: CanonicalSubmission,
    pub(crate) resolved: ResolvedJob,
    pub(crate) original_inputs: BTreeMap<String, InputIdentity>,
    pub(crate) request_bytes: usize,
    pub(crate) binding_bytes: usize,
    pub(crate) metadata_bytes: usize,
    pub(crate) response_bytes: usize,
    pub(crate) obj_summaries: BTreeMap<String, ObjSummary>,
    _pinned_inputs: PinnedInputSet,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedAdmission {
    resolved: ResolvedSelection,
    readiness: PreparedReadiness,
}

impl PreparedAdmission {
    /// The only current constructor accepts a fixture loaded after the complete
    /// package, probe and integrity manifest have been verified.
    #[cfg(feature = "test-support")]
    pub(crate) fn from_verified_fixture(value: &FixtureReadiness) -> Self {
        Self {
            resolved: value.resolved.clone(),
            readiness: value.snapshot.clone(),
        }
    }

    /// Whether a retained resolution is exactly the one currently prepared:
    /// the same selection snapshot and readiness. Nothing is re-resolved.
    pub(crate) fn covers(&self, resolved: &ResolvedJob) -> bool {
        resolved.selection == selection_snapshot(&self.resolved)
            && resolved.readiness == self.readiness
    }
}

#[cfg(unix)]
pub(crate) fn build_candidate(
    catalog: &Catalog,
    prepared: &PreparedAdmission,
    request: &JobRequest,
    request_bytes: usize,
    pinned_inputs: PinnedInputSet,
    input_readers: BTreeMap<String, Box<dyn Read + Send>>,
) -> Result<AdmissionCandidate, AdmissionError> {
    build_candidate_inner(
        catalog,
        prepared,
        request,
        request_bytes,
        pinned_inputs,
        input_readers,
        None,
    )
}
pub(crate) fn build_execution_candidate(
    catalog: &Catalog,
    prepared: &PreparedAdmission,
    request: &dissect3d_api::ExecutionJobRequest,
    request_bytes: usize,
    pinned_inputs: PinnedInputSet,
    input_readers: BTreeMap<String, Box<dyn Read + Send>>,
) -> Result<AdmissionCandidate, AdmissionError> {
    dissect3d_api::encode_execution_request(request).map_err(|_| AdmissionError::InvalidRequest)?;
    build_candidate_inner(
        catalog,
        prepared,
        &request.request,
        request_bytes,
        pinned_inputs,
        input_readers,
        Some(&request.execution),
    )
}
#[allow(clippy::too_many_arguments)]
fn build_candidate_inner(
    catalog: &Catalog,
    prepared: &PreparedAdmission,
    request: &JobRequest,
    request_bytes: usize,
    pinned_inputs: PinnedInputSet,
    mut input_readers: BTreeMap<String, Box<dyn Read + Send>>,
    execution: Option<&dissect3d_api::ExecutionPolicy>,
) -> Result<AdmissionCandidate, AdmissionError> {
    if request_bytes > REQUEST_BYTES_MAX
        || request.inputs.is_empty()
        || request.inputs.len() > ROLES_MAX
        || request.required_features.len() > REQUIRED_FEATURES_MAX
    {
        return Err(AdmissionError::InvalidRequest);
    }
    let occurrence_count = request
        .inputs
        .values()
        .try_fold(0usize, |count, values| count.checked_add(values.len()));
    let Some(occurrence_count) = occurrence_count else {
        return Err(AdmissionError::InvalidRequest);
    };
    if occurrence_count == 0 || occurrence_count > INPUT_OCCURRENCES_MAX {
        return Err(AdmissionError::InvalidRequest);
    }
    if (execution.is_none() && !request.required_features.is_empty())
        || (execution.is_some() && request.required_features != [dissect3d_api::EXECUTION_FEATURE])
    {
        return Err(AdmissionError::RequiredFeatureUnsupported);
    }

    let task = dissect3d_api::TaskKey::new(&request.task.id, &request.task.version)
        .map_err(|_| AdmissionError::UnsupportedSelection)?;
    let selection = Selection {
        support_ref: request.support_ref.clone(),
        task,
        runtime_ref: request.runtime_ref.clone(),
        variant: request.variant.clone(),
    };
    let resolved_selection = catalog
        .resolve(&selection)
        .map_err(|_| AdmissionError::UnsupportedSelection)?;
    if resolved_selection != prepared.resolved {
        return Err(AdmissionError::NotPrepared);
    }

    let model = catalog
        .model(&request.support_ref)
        .ok_or(AdmissionError::UnsupportedSelection)?;
    let task_binding = model
        .tasks
        .iter()
        .find(|binding| binding.task == selection.task)
        .ok_or(AdmissionError::UnsupportedSelection)?;
    if !model.test_only
        || !model.unresolved_paths.is_empty()
        || !task_binding.unresolved_paths.is_empty()
        || !model.declaration["required_features"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || !task_binding.binding["constraints"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || !task_binding.binding["preprocessing"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || task_binding.binding["validator"]["id"] != dissect3d_api::TEST_OUTPUT_VALIDATOR_ID
        || task_binding.binding["validator"]["revision"]
            != dissect3d_api::TEST_OUTPUT_VALIDATOR_REVISION
    {
        return Err(AdmissionError::UnsupportedSelection);
    }

    let input_schema = schema_for_binding(task_binding, "input_schema")?;
    let parameter_schema = schema_for_binding(task_binding, "parameter_schema")?;
    let output_schema = schema_for_binding(task_binding, "output_schema")?;
    validate_known_schemas(input_schema, parameter_schema, output_schema)?;
    let effective_parameters = resolve_parameters(request, parameter_schema)?;
    validate_fixture_inputs(request)?;

    let identities = pinned_inputs
        .identities
        .iter()
        .map(|identity| (identity.input_id.as_str().to_owned(), identity.clone()))
        .collect::<VerifiedInputMap>();
    if identities.len() != pinned_inputs.identities.len() {
        return Err(AdmissionError::InputUnavailable);
    }
    let requested_ids = request
        .inputs
        .values()
        .flatten()
        .map(|reference| reference.input_id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if requested_ids.len() != identities.len()
        || requested_ids.iter().any(|id| !identities.contains_key(id))
        || input_readers.len() != identities.len()
        || input_readers.keys().any(|id| !identities.contains_key(id))
    {
        return Err(AdmissionError::InputUnavailable);
    }
    let mut total_input_bytes = 0u64;
    let mut obj_summaries = BTreeMap::new();
    for references in request.inputs.values() {
        for reference in references {
            let key = reference.input_id.as_str();
            let identity = identities
                .get(key)
                .ok_or(AdmissionError::InputUnavailable)?;
            if identity.media_type != "application/octet-stream"
                || identity.byte_length > INPUT_BYTES_MAX
            {
                return Err(AdmissionError::InvalidInput);
            }
            if identity.byte_length > super::obj::MAX_BYTES as u64 {
                return Err(AdmissionError::InvalidInput);
            }
            total_input_bytes = total_input_bytes
                .checked_add(identity.byte_length)
                .ok_or(AdmissionError::CapacityExceeded)?;
            if total_input_bytes > JOB_INPUT_BYTES_MAX {
                return Err(AdmissionError::CapacityExceeded);
            }
        }
    }
    for key in requested_ids {
        let identity = identities
            .get(&key)
            .ok_or(AdmissionError::InputUnavailable)?;
        let reader = input_readers
            .remove(&key)
            .ok_or(AdmissionError::InputUnavailable)?;
        let mut reader = HashingReader::new(reader, identity.byte_length.saturating_add(1));
        let permit = ValidationPermit::acquire().map_err(map_obj_error)?;
        let deadline = std::time::Instant::now() + VALIDATION_WALL_BUDGET;
        let validation = validate_obj_in(&mut reader, deadline, &permit);
        if validation == Err(ObjError::Deadline) {
            return Err(AdmissionError::CapacityExceeded);
        }
        let mut trailing = [0_u8; 8192];
        while reader.bytes <= identity.byte_length {
            check_deadline(deadline).map_err(map_obj_error)?;
            match reader.read(&mut trailing) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => return Err(AdmissionError::StorageIntegrityFault),
            }
        }
        check_deadline(deadline).map_err(map_obj_error)?;
        if reader.bytes != identity.byte_length
            || digest_hex(&reader.hasher.clone().finalize()) != identity.sha256.as_str()
        {
            return Err(AdmissionError::StorageIntegrityFault);
        }
        let summary = validation.map_err(map_obj_error)?;
        obj_summaries.insert(key, summary);
    }

    let submitted = match execution {
        Some(policy) => {
            super::equivalence::SubmittedJobRequest::Execution(dissect3d_api::ExecutionJobRequest {
                request: request.clone(),
                execution: policy.clone(),
            })
        }
        None => super::equivalence::SubmittedJobRequest::Legacy(request.clone()),
    };
    let canonical = submitted
        .canonicalize(&identities)
        .map_err(|_| AdmissionError::InvalidRequest)?;
    if canonical.bytes.len() > CANONICAL_BYTES_MAX {
        return Err(AdmissionError::CapacityExceeded);
    }
    let original_inputs = identities
        .iter()
        .map(|(id, identity)| (id.clone(), identity.clone()))
        .collect::<BTreeMap<_, _>>();
    let resolved_inputs = request
        .inputs
        .iter()
        .map(|(role, values)| {
            let identities = values
                .iter()
                .map(|reference| {
                    identities
                        .get(reference.input_id.as_str())
                        .cloned()
                        .ok_or(AdmissionError::InputUnavailable)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((role.clone(), identities))
        })
        .collect::<Result<BTreeMap<_, _>, AdmissionError>>()?;

    let resolved = ResolvedJob {
        selection: selection_snapshot(&resolved_selection),
        effective_parameters,
        inputs: resolved_inputs,
        readiness: prepared.readiness.clone(),
        validation: vec![ValidationEvidence {
            validator_id: dissect3d_api::TEST_OUTPUT_VALIDATOR_ID.to_owned(),
            revision: dissect3d_api::TEST_OUTPUT_VALIDATOR_REVISION.to_owned(),
            status: "passed".to_owned(),
        }],
        evidence_scope: "controlled-test-only".to_owned(),
    };
    let binding = BindingMetadata {
        canonicalization_version: canonical.version.as_i64(),
        fingerprint: digest_hex(&canonical.fingerprint),
        original_inputs: &original_inputs,
    };
    let (binding_bytes, mut metadata_bytes) = metadata_size(&resolved, &binding)?;
    if let Some(policy) = execution {
        let n = serde_json::to_vec(policy)
            .map_err(|_| AdmissionError::CapacityExceeded)?
            .len();
        metadata_bytes = metadata_bytes
            .checked_add(n + 2048)
            .ok_or(AdmissionError::CapacityExceeded)?;
    }
    if binding_bytes > BINDING_BYTES_MAX {
        return Err(AdmissionError::CapacityExceeded);
    }
    if metadata_bytes > METADATA_BYTES_MAX {
        return Err(AdmissionError::CapacityExceeded);
    }
    let response_bytes = response_fit_bytes(&resolved)?;
    if response_bytes > RESPONSE_BYTES_MAX {
        return Err(AdmissionError::CapacityExceeded);
    }

    Ok(AdmissionCandidate {
        canonical,
        resolved,
        original_inputs,
        request_bytes,
        binding_bytes,
        metadata_bytes,
        response_bytes,
        obj_summaries,
        _pinned_inputs: pinned_inputs,
    })
}

fn metadata_size(
    resolved: &ResolvedJob,
    binding: &BindingMetadata<'_>,
) -> Result<(usize, usize), AdmissionError> {
    let binding_bytes = serde_json::to_vec(binding)
        .map_err(|_| AdmissionError::CapacityExceeded)?
        .len();
    let snapshot_bytes = response_fit_bytes(resolved)?;
    let event_bytes = serde_json::to_vec(&AcceptanceEventFit {
        job_id: "job_ffffffffffffffffffffffffffffffff",
        acceptance_sequence: i64::MAX,
        snapshot_revision: u64::MAX,
    })
    .map_err(|_| AdmissionError::CapacityExceeded)?
    .len();
    let metadata_bytes = snapshot_bytes
        .checked_add(binding_bytes)
        .and_then(|size| size.checked_add(event_bytes))
        .ok_or(AdmissionError::CapacityExceeded)?;
    Ok((binding_bytes, metadata_bytes))
}

fn selection_snapshot(selection: &ResolvedSelection) -> SelectionSnapshot {
    SelectionSnapshot {
        support_id: selection.support_id.clone(),
        support_ref: selection.support_ref.clone(),
        support_sha256: selection.support_sha256.clone(),
        code: CodeSnapshot {
            upstream_repository: selection.code.upstream_repository.clone(),
            upstream_revision: selection.code.upstream_revision.clone(),
            executed_repository: selection.code.executed_repository.clone(),
            executed_revision: selection.code.executed_revision.clone(),
            patches: selection
                .code
                .patches
                .iter()
                .map(|patch| PatchSnapshot {
                    id: patch.id.clone(),
                    sha256: patch.sha256.clone(),
                })
                .collect(),
            build_provenance: selection.code.build_provenance.clone(),
        },
        adapter: AdapterSnapshot {
            id: selection.adapter.id.clone(),
            revision: selection.adapter.revision.clone(),
            sha256: selection.adapter.sha256.clone(),
            interface_version: selection.adapter.interface_version.clone(),
            required_worker_features: selection.adapter.required_worker_features.clone(),
        },
        assets: selection
            .assets
            .iter()
            .map(|asset| AssetSnapshot {
                id: asset.id.clone(),
                kind: asset.kind.clone(),
                source: asset.source.clone(),
                revision: asset.revision.clone(),
                sha256: asset.sha256.clone(),
                byte_length: asset.byte_length,
                prerequisites: asset.prerequisites.clone(),
                rights_id: asset.rights_id.clone(),
            })
            .collect(),
        task_binding_id: selection.task_binding_id.clone(),
        task: SubmittedTask {
            id: selection.task.id().to_owned(),
            version: selection.task.version().to_owned(),
        },
        schemas: selection
            .schemas
            .iter()
            .map(|schema| SchemaSnapshot {
                id: schema.id.clone(),
                version: schema.version.clone(),
                sha256: schema.sha256.clone(),
            })
            .collect(),
        runtime_id: selection.runtime_id.clone(),
        runtime_ref: selection.runtime_ref.clone(),
        runtime_sha256: selection.runtime_sha256.clone(),
        variant: selection.variant.clone(),
    }
}

fn response_fit_bytes(resolved: &ResolvedJob) -> Result<usize, AdmissionError> {
    let job_id = JobId::parse("job_ffffffffffffffffffffffffffffffff")
        .map_err(|_| AdmissionError::CapacityExceeded)?;
    let timestamp =
        TimestampMs::new(i64::MAX as u64).map_err(|_| AdmissionError::CapacityExceeded)?;
    let receipt = AcceptanceReceipt {
        api_version: "1.0".to_owned(),
        accepted: true,
        job_id: job_id.clone(),
        replayed: false,
        acceptance_sequence: i64::MAX,
        snapshot_revision: u64::MAX,
        resolved: resolved.clone(),
    };
    let receipt_bytes = serde_json::to_vec(&receipt)
        .map_err(|_| AdmissionError::CapacityExceeded)?
        .len();
    let snapshot = JobSnapshot {
        api_version: "1.0".to_owned(),
        summary: JobSummary {
            job_id,
            acceptance_sequence: i64::MAX,
            snapshot_revision: u64::MAX,
            state: JobState::Queued,
            blockers: vec!["execution_not_implemented".to_owned()],
            created_at_ms: timestamp,
        },
        resolved: resolved.clone(),
        storage_status: StorageStatus::Verified,
        attempt_id: None,
        result_id: None,
    };
    let show_bytes = serde_json::to_vec(&snapshot)
        .map_err(|_| AdmissionError::CapacityExceeded)?
        .len();
    Ok(receipt_bytes.max(show_bytes))
}

fn map_obj_error(error: ObjError) -> AdmissionError {
    match error {
        ObjError::Capacity | ObjError::LimitExceeded | ObjError::TooLarge => {
            AdmissionError::CapacityExceeded
        }
        ObjError::Deadline => AdmissionError::CapacityExceeded,
        ObjError::InvalidUtf8 | ObjError::InvalidGrammar => AdmissionError::InvalidInput,
    }
}

fn digest_hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

struct HashingReader<R> {
    reader: R,
    hasher: Sha256,
    bytes: u64,
    remaining: u64,
}

impl<R> HashingReader<R> {
    fn new(reader: R, maximum: u64) -> Self {
        Self {
            reader,
            hasher: Sha256::new(),
            bytes: 0,
            remaining: maximum,
        }
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let allowed = usize::try_from(self.remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("input read length overflow"))?;
        let length = self.reader.read(&mut buffer[..allowed])?;
        self.hasher.update(&buffer[..length]);
        self.bytes = self
            .bytes
            .checked_add(length as u64)
            .ok_or_else(|| io::Error::other("input length overflow"))?;
        self.remaining -= length as u64;
        Ok(length)
    }
}

#[derive(Serialize)]
struct BindingMetadata<'a> {
    canonicalization_version: i64,
    fingerprint: String,
    original_inputs: &'a BTreeMap<String, InputIdentity>,
}

#[derive(Serialize)]
struct AcceptanceEventFit {
    job_id: &'static str,
    acceptance_sequence: i64,
    snapshot_revision: u64,
}

#[cfg(all(test, feature = "test-support"))]
#[path = "admission_tests.rs"]
mod tests;
