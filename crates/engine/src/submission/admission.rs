//! Bounded fresh-request admission facts retained through atomic acceptance.

use super::equivalence::{
    CanonicalSubmission, CanonicalizationVersion, VerifiedInputMap, canonicalize,
};
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
}

#[cfg(unix)]
pub(crate) fn build_candidate(
    catalog: &Catalog,
    prepared: &PreparedAdmission,
    request: &JobRequest,
    request_bytes: usize,
    pinned_inputs: PinnedInputSet,
    mut input_readers: BTreeMap<String, Box<dyn Read + Send>>,
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
    if !request.required_features.is_empty() {
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
        || task_binding.binding["validator"]["id"] != "dissect3d.test.validator"
        || task_binding.binding["validator"]["revision"] != "1"
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

    let canonical = canonicalize(request, &identities).map_err(|error| match error {
        super::equivalence::CanonicalError::MissingInput => AdmissionError::InputUnavailable,
        super::equivalence::CanonicalError::InvalidDecimal => AdmissionError::InvalidRequest,
        super::equivalence::CanonicalError::TooLarge => AdmissionError::CapacityExceeded,
    })?;
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
            validator_id: "dissect3d.test.validator".to_owned(),
            revision: "1".to_owned(),
            status: "passed".to_owned(),
        }],
        evidence_scope: "controlled-test-only".to_owned(),
    };
    let binding = BindingMetadata {
        canonicalization_version: CanonicalizationVersion::V1.as_i64(),
        fingerprint: digest_hex(&canonical.fingerprint),
        original_inputs: &original_inputs,
    };
    let (binding_bytes, metadata_bytes) = metadata_size(&resolved, &binding)?;
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
mod tests {
    use super::*;
    use crate::CorePolicy;
    use crate::credentials::VerifiedEnrollment;
    use crate::store::{DurableInput, Store};
    use dissect3d_api::SubmissionValue;
    use dissect3d_api::{ClientId, EnrollmentId, TokenDigest, decode_job_request};
    use dissect3d_platform::{
        AuthorityLease, OwnedRoot, RelativePath, RootPurpose, current_owner_identity,
    };
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read};
    use tempfile::TempDir;

    struct Fixture {
        _parent: TempDir,
        root: OwnedRoot,
        store: Store,
        context: crate::AuthContext,
        prepared: crate::submission_fixture::PreparedFixture,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_policy(CorePolicy::default())
        }

        fn with_policy(policy: CorePolicy) -> Self {
            let parent = tempfile::tempdir().expect("temporary fixture parent");
            let root_path = parent.path().join("engine");
            let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
                .expect("private fixture root");
            let lease = AuthorityLease::acquire(&root).expect("fixture authority lease");
            let store = Store::open(root, lease, &policy).expect("fixture store");
            let identity = store.identity().expect("fixture identity");
            let client_id =
                ClientId::parse("cli_2223456789abcdef0123456789abcdef").expect("fixture client ID");
            let token_digest = TokenDigest::new(Sha256::digest([0x42; 32]).into());
            store
                .enroll(VerifiedEnrollment::new_submission_access(
                    current_owner_identity().expect("fixture owner"),
                    identity.installation_id,
                    identity.instance_id,
                    EnrollmentId::parse("enr_2223456789abcdef0123456789abcdef")
                        .expect("fixture enrollment ID"),
                    client_id.clone(),
                    token_digest.clone(),
                ))
                .expect("submission grant enrollment");
            let context = store
                .authenticate(client_id, token_digest)
                .expect("submission authorization");
            let root =
                OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("open input file root");
            let prepared = crate::submission_fixture::verified_fixture_for_admission(&root);
            Self {
                _parent: parent,
                root,
                store,
                context,
                prepared,
            }
        }

        fn capture(&self, bytes: &[u8]) -> InputIdentity {
            let reservation = self
                .store
                .reserve_upload(
                    self.context.clone(),
                    bytes.len() as u64,
                    "application/octet-stream".to_owned(),
                    self.root
                        .available_space_bytes()
                        .expect("filesystem capacity"),
                )
                .expect("reserve input");
            let staged = RelativePath::parse(format!(
                "inputs/staging/{}.part",
                reservation.input_id.as_str()
            ))
            .expect("staging path");
            let final_path =
                RelativePath::parse(format!("inputs/data/{}.bin", reservation.input_id.as_str()))
                    .expect("immutable input path");
            let mut writer = self.root.begin_input(&staged).expect("create staging file");
            writer.write_chunk(bytes).expect("write captured bytes");
            let file = writer.finish(&final_path).expect("publish input file");
            self.store
                .complete_upload(
                    self.context.clone(),
                    reservation,
                    DurableInput {
                        file,
                        sha256: Sha256::digest(bytes).into(),
                    },
                )
                .expect("commit captured identity")
                .identity
        }

        fn candidate(
            &self,
            catalog: &Catalog,
            input: &InputIdentity,
            parameters: &str,
            required_features: &str,
        ) -> Result<AdmissionCandidate, AdmissionError> {
            let prepared = PreparedAdmission::from_verified_fixture(&self.prepared.readiness);
            self.candidate_with_prepared(catalog, input, parameters, required_features, &prepared)
        }

        fn candidate_with_prepared(
            &self,
            catalog: &Catalog,
            input: &InputIdentity,
            parameters: &str,
            required_features: &str,
            prepared: &PreparedAdmission,
        ) -> Result<AdmissionCandidate, AdmissionError> {
            let request_bytes =
                request_bytes(input.input_id.as_str(), parameters, required_features);
            let request = decode_job_request(&request_bytes).expect("strict fixture request");
            let pinned = self
                .store
                .pin_verified_inputs(self.context.clone(), vec![input.input_id.clone()])
                .expect("actor-issued authorization and input pin");
            let path = RelativePath::parse(format!("inputs/data/{}.bin", input.input_id.as_str()))
                .expect("input file path");
            let mut reader = self
                .root
                .open_immutable_input(&path)
                .expect("open immutable input");
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .expect("read pinned input bytes");
            let contents = BTreeMap::from([(
                input.input_id.as_str().to_owned(),
                Box::new(Cursor::new(bytes)) as Box<dyn Read + Send>,
            )]);
            build_candidate(
                catalog,
                prepared,
                &request,
                request_bytes.len(),
                pinned,
                contents,
            )
        }

        fn request_candidate(
            &self,
            input: &InputIdentity,
            parameters: &str,
            required_features: &str,
        ) -> Result<AdmissionCandidate, AdmissionError> {
            self.candidate(&self.prepared.catalog, input, parameters, required_features)
        }
    }

    #[test]
    fn atomic_acceptance_commits_one_job_binding_event_and_retained_reference() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let candidate = fixture.request_candidate(&input, "{}", "[]").unwrap();
        let key = dissect3d_api::IdempotencyKey::parse("atomic-key").unwrap();
        let receipt = fixture
            .store
            .accept_job(
                fixture.context.clone(),
                key.clone(),
                request.clone(),
                candidate,
            )
            .unwrap();
        assert!(!receipt.replayed);
        assert_eq!(receipt.acceptance_sequence, 1);
        assert!(
            fixture
                .store
                .claim_input_cleanup_at(i64::MAX)
                .unwrap()
                .is_empty(),
            "accepted inputs never expire"
        );
        let replay = fixture
            .store
            .probe_job_binding(fixture.context.clone(), key, request)
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.job_id, receipt.job_id);
        let path = fixture.root.path().join("metadata.sqlite3");
        drop(fixture.store);
        let db = rusqlite::Connection::open(path).unwrap();
        for table in [
            "jobs",
            "submission_bindings",
            "job_acceptance_events",
            "job_inputs",
        ] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn acceptance_commit_failure_rolls_back_every_effect_and_sequence() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let key = dissect3d_api::IdempotencyKey::parse("rollback-key").unwrap();
        let candidate = fixture.request_candidate(&input, "{}", "[]").unwrap();
        fixture.store.fail_next_job_commit().unwrap();
        assert_eq!(
            fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    key.clone(),
                    request.clone(),
                    candidate
                )
                .unwrap_err()
                .code,
            dissect3d_api::ErrorCode::StoreUnavailable
        );
        assert!(
            fixture
                .store
                .probe_job_binding(fixture.context.clone(), key.clone(), request.clone())
                .unwrap()
                .is_none()
        );
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "submission_bindings",
            "job_acceptance_events",
            "job_inputs",
        ] {
            let count: i64 = db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table}");
        }
        let candidate = fixture.request_candidate(&input, "{}", "[]").unwrap();
        let accepted = fixture
            .store
            .accept_job(fixture.context.clone(), key, request, candidate)
            .unwrap();
        assert_eq!(accepted.acceptance_sequence, 1);
    }

    #[test]
    fn retained_replacement_ids_remain_eligible_after_staging_expiry() {
        let fixture = Fixture::new();
        let a = fixture.capture(TETRAHEDRON);
        let b = fixture.capture(TETRAHEDRON);
        let request_a =
            decode_job_request(&request_bytes(a.input_id.as_str(), "{}", "[]")).unwrap();
        let request_b =
            decode_job_request(&request_bytes(b.input_id.as_str(), "{}", "[]")).unwrap();
        let key_a = dissect3d_api::IdempotencyKey::parse("retained-a").unwrap();
        let key_b = dissect3d_api::IdempotencyKey::parse("retained-b").unwrap();
        let accepted = fixture
            .store
            .accept_job(
                fixture.context.clone(),
                key_a.clone(),
                request_a,
                fixture.request_candidate(&a, "{}", "[]").unwrap(),
            )
            .unwrap();
        fixture
            .store
            .accept_job(
                fixture.context.clone(),
                key_b,
                request_b.clone(),
                fixture.request_candidate(&b, "{}", "[]").unwrap(),
            )
            .unwrap();
        assert!(
            fixture
                .store
                .claim_input_cleanup_at(i64::MAX)
                .unwrap()
                .is_empty()
        );
        let replay = fixture
            .store
            .probe_job_binding(fixture.context.clone(), key_a, request_b)
            .unwrap()
            .unwrap();
        assert_eq!(replay.job_id, accepted.job_id);
        assert!(
            fixture.request_candidate(&b, "{}", "[]").is_ok(),
            "a retained creator-owned input remains available for fresh work"
        );
    }

    fn request_bytes(input_id: &str, parameters: &str, required_features: &str) -> Vec<u8> {
        format!(
            "{{\"api_version\":\"1.0\",\"support_ref\":\"test.mesh-copy@fixture-r1\",\"task\":{{\"id\":\"dissect3d.test.mesh-copy\",\"version\":\"1.0\"}},\"inputs\":{{\"mesh\":[{{\"input_id\":\"{input_id}\"}}]}},\"parameters\":{parameters},\"required_features\":{required_features},\"evaluation_consent\":false}}"
        )
        .into_bytes()
    }

    const TETRAHEDRON: &[u8] = include_bytes!("../../tests/fixtures/submission/tetrahedron.obj");

    #[test]
    fn fresh_prepared_fixture_builds_owned_candidate_and_resolves_only_declared_defaults() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let candidate = fixture
            .request_candidate(&input, "{}", "[]")
            .expect("prepared fixture candidate");
        assert_eq!(candidate.canonical.version, CanonicalizationVersion::V1);
        assert_eq!(
            candidate.resolved.selection.support_ref,
            "test.mesh-copy@fixture-r1"
        );
        assert_eq!(candidate.resolved.inputs["mesh"][0], input);
        assert_eq!(candidate.original_inputs.len(), 1);
        assert!(candidate.request_bytes <= REQUEST_BYTES_MAX);
        assert_eq!(
            candidate.resolved.effective_parameters["hold_before_candidate"],
            SubmissionValue::Bool(false)
        );
        assert_eq!(
            candidate.resolved.effective_parameters["fail_execution"],
            SubmissionValue::Bool(false)
        );
        assert_eq!(candidate.obj_summaries[input.input_id.as_str()].faces, 4);
        assert!(candidate.binding_bytes <= BINDING_BYTES_MAX);
        assert!(candidate.metadata_bytes <= METADATA_BYTES_MAX);
        assert!(candidate.response_bytes <= RESPONSE_BYTES_MAX);

        let mut oversized = candidate.resolved.clone();
        let response_padding = RESPONSE_BYTES_MAX - candidate.response_bytes;
        oversized
            .evidence_scope
            .push_str(&"x".repeat(response_padding));
        assert_eq!(
            response_fit_bytes(&oversized).expect("exact final response boundary"),
            RESPONSE_BYTES_MAX
        );
        oversized.evidence_scope.push('x');
        assert!(
            response_fit_bytes(&oversized).expect("measure final response") > RESPONSE_BYTES_MAX
        );

        let binding = BindingMetadata {
            canonicalization_version: candidate.canonical.version.as_i64(),
            fingerprint: digest_hex(&candidate.canonical.fingerprint),
            original_inputs: &candidate.original_inputs,
        };
        let (_, metadata_bytes) =
            metadata_size(&candidate.resolved, &binding).expect("initial metadata size");
        let mut metadata_boundary = candidate.resolved.clone();
        metadata_boundary
            .evidence_scope
            .push_str(&"x".repeat(METADATA_BYTES_MAX - metadata_bytes));
        assert_eq!(
            metadata_size(&metadata_boundary, &binding)
                .expect("exact aggregate metadata boundary")
                .1,
            METADATA_BYTES_MAX
        );
        metadata_boundary.evidence_scope.push('x');
        assert!(
            metadata_size(&metadata_boundary, &binding)
                .expect("one byte beyond aggregate metadata")
                .1
                > METADATA_BYTES_MAX
        );
    }

    #[test]
    fn unknown_parameters_features_schema_semantics_and_invalid_mesh_are_rejected() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        assert!(matches!(
            fixture.request_candidate(&input, "{\"unknown\":true}", "[]"),
            Err(AdmissionError::UnsupportedParameter)
        ));
        assert!(matches!(
            fixture.request_candidate(&input, "{}", "[\"future.feature\"]"),
            Err(AdmissionError::RequiredFeatureUnsupported)
        ));

        let mut changed_catalog = fixture.prepared.catalog.clone();
        let model = changed_catalog
            .models
            .values_mut()
            .next()
            .expect("fixture model");
        model.tasks[0].binding["preprocessing"] = serde_json::json!([{"kind":"unknown"}]);
        assert!(matches!(
            fixture.candidate(&changed_catalog, &input, "{}", "[]"),
            Err(AdmissionError::UnsupportedSelection)
        ));

        let mut unknown_schema = fixture.prepared.catalog.clone();
        let unknown_model = unknown_schema
            .models
            .values_mut()
            .next()
            .expect("fixture model");
        let input_schema = unknown_model.tasks[0]
            .schemas
            .iter_mut()
            .find(|schema| schema.document["id"] == "test.mesh")
            .expect("fixture input schema");
        input_schema.document["id"] = Value::String("test.unknown".to_owned());
        let mut unknown_prepared =
            PreparedAdmission::from_verified_fixture(&fixture.prepared.readiness);
        unknown_prepared
            .resolved
            .schemas
            .iter_mut()
            .find(|schema| schema.id == "test.mesh")
            .expect("input schema identity")
            .id = "test.unknown".to_owned();
        assert!(matches!(
            fixture
                .candidate_with_prepared(&unknown_schema, &input, "{}", "[]", &unknown_prepared,),
            Err(AdmissionError::UnsupportedSelection)
        ));

        let invalid = fixture
            .capture(b"v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nf 1 3 2\nf 1 3 2\nf 1 4 3\nf 2 3 4\n");
        assert!(matches!(
            fixture.request_candidate(&invalid, "{}", "[]"),
            Err(AdmissionError::InvalidInput)
        ));
    }

    #[test]
    fn fixture_integrity_mismatch_rejects_before_candidate_entry() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let pinned = fixture
            .store
            .pin_verified_inputs(fixture.context.clone(), vec![input.input_id.clone()])
            .expect("pin input");
        let request_bytes = request_bytes(input.input_id.as_str(), "{}", "[]");
        let request = decode_job_request(&request_bytes).expect("strict request");
        let mut contents = BTreeMap::new();
        contents.insert(
            input.input_id.as_str().to_owned(),
            Box::new(Cursor::new(b"tampered file bytes".to_vec())) as Box<dyn Read + Send>,
        );
        let prepared = PreparedAdmission::from_verified_fixture(&fixture.prepared.readiness);
        assert!(matches!(
            build_candidate(
                &fixture.prepared.catalog,
                &prepared,
                &request,
                request_bytes.len(),
                pinned,
                contents,
            ),
            Err(AdmissionError::StorageIntegrityFault)
        ));
    }
    #[test]
    fn concurrent_candidates_bind_once_and_conflicts_never_charge_capacity() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let candidates: Vec<_> = (0..4)
            .map(|_| fixture.request_candidate(&input, "{}", "[]").unwrap())
            .collect();
        let key = dissect3d_api::IdempotencyKey::parse("four-candidates").unwrap();
        let barrier = std::sync::Barrier::new(4);
        let receipts = std::thread::scope(|scope| {
            let threads: Vec<_> = candidates
                .into_iter()
                .map(|candidate| {
                    let (barrier, store, auth, key, request) = (
                        &barrier,
                        &fixture.store,
                        fixture.context.clone(),
                        key.clone(),
                        request.clone(),
                    );
                    scope.spawn(move || {
                        barrier.wait();
                        store.accept_job(auth, key, request, candidate).unwrap()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            receipts.iter().filter(|receipt| !receipt.replayed).count(),
            1
        );
        assert!(
            receipts
                .iter()
                .all(|receipt| receipt.job_id == receipts[0].job_id
                    && receipt.acceptance_sequence == 1
                    && receipt.resolved == receipts[0].resolved)
        );
        let changed = decode_job_request(&request_bytes(
            input.input_id.as_str(),
            "{\"fail_execution\":true}",
            "[]",
        ))
        .unwrap();
        assert_eq!(
            fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    key,
                    changed,
                    fixture
                        .request_candidate(&input, "{\"fail_execution\":true}", "[]")
                        .unwrap()
                )
                .unwrap_err()
                .code,
            dissect3d_api::ErrorCode::IdempotencyConflict
        );
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
    }

    #[test]
    fn queue_exhaustion_does_not_block_replay_or_add_partial_effects() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let mut first = None;
        for index in 0..128 {
            let receipt = fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    dissect3d_api::IdempotencyKey::parse(format!("capacity-{index}")).unwrap(),
                    request.clone(),
                    fixture.request_candidate(&input, "{}", "[]").unwrap(),
                )
                .unwrap();
            assert_eq!(receipt.acceptance_sequence, index + 1);
            if index == 0 {
                first = Some(receipt);
            }
        }
        let problem = fixture
            .store
            .accept_job(
                fixture.context.clone(),
                dissect3d_api::IdempotencyKey::parse("capacity-overflow").unwrap(),
                request.clone(),
                fixture.request_candidate(&input, "{}", "[]").unwrap(),
            )
            .unwrap_err();
        assert_eq!(problem.limit, Some("queued_jobs_max"));
        let replay = fixture
            .store
            .accept_job(
                fixture.context.clone(),
                dissect3d_api::IdempotencyKey::parse("capacity-0").unwrap(),
                request,
                fixture.request_candidate(&input, "{}", "[]").unwrap(),
            )
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.job_id, first.unwrap().job_id);
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                128
            );
        }
        assert_eq!(
            db.query_row("SELECT count(*) FROM captured_inputs", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn effective_response_budget_rejects_before_any_acceptance_effect() {
        let fixture = Fixture::with_policy(CorePolicy {
            control_response_bytes: 128,
            ..CorePolicy::default()
        });
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let key = dissect3d_api::IdempotencyKey::parse("response-cap").unwrap();
        assert_eq!(
            fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    key.clone(),
                    request.clone(),
                    fixture.request_candidate(&input, "{}", "[]").unwrap()
                )
                .unwrap_err()
                .code,
            dissect3d_api::ErrorCode::CapacityExceeded
        );
        assert!(
            fixture
                .store
                .probe_job_binding(fixture.context.clone(), key, request)
                .unwrap()
                .is_none()
        );
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM job_sequence", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM jobs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn final_acceptance_rechecks_revocation_stop_and_expiry_in_both_orders() {
        for boundary in ["revoke", "stop", "expire"] {
            for accept_first in [false, true] {
                let fixture = Fixture::new();
                let input = fixture.capture(TETRAHEDRON);
                let request =
                    decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]"))
                        .unwrap();
                let candidate = fixture.request_candidate(&input, "{}", "[]").unwrap();
                let key = dissect3d_api::IdempotencyKey::parse("ordered-acceptance").unwrap();
                let accept = || {
                    fixture.store.accept_job(
                        fixture.context.clone(),
                        key.clone(),
                        request.clone(),
                        candidate,
                    )
                };
                let boundary_action = || match boundary {
                    "revoke" => {
                        fixture.store.revoke_self(fixture.context.clone()).unwrap();
                    }
                    "stop" => {
                        fixture
                            .store
                            .signal_shutdown(fixture.store.identity().unwrap().instance_id, 5000)
                            .unwrap();
                    }
                    _ => {
                        fixture.store.claim_input_cleanup_at(i64::MAX).unwrap();
                    }
                };
                if accept_first {
                    let receipt = accept().unwrap();
                    boundary_action();
                    let replay =
                        fixture
                            .store
                            .probe_job_binding(fixture.context.clone(), key, request);
                    if boundary == "revoke" {
                        assert_eq!(
                            replay.unwrap_err().code,
                            dissect3d_api::ErrorCode::Unauthorized
                        );
                    } else {
                        assert_eq!(replay.unwrap().unwrap().job_id, receipt.job_id);
                    }
                } else {
                    boundary_action();
                    let error = accept().unwrap_err();
                    assert_eq!(
                        error.code,
                        match boundary {
                            "revoke" => dissect3d_api::ErrorCode::Unauthorized,
                            "stop" => dissect3d_api::ErrorCode::EngineStopping,
                            _ => dissect3d_api::ErrorCode::InputUnavailable,
                        }
                    );
                    let db =
                        rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3"))
                            .unwrap();
                    assert_eq!(
                        db.query_row("SELECT count(*) FROM jobs", [], |row| row.get::<_, i64>(0))
                            .unwrap(),
                        0
                    );
                }
            }
        }
    }
    #[test]
    fn cursor_scope_and_snapshot_budget_are_enforced_without_losing_history() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use dissect3d_api::{ErrorCode, JobsQuery};
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let mut receipts = Vec::new();
        for index in 0..3 {
            receipts.push(
                fixture
                    .store
                    .accept_job(
                        fixture.context.clone(),
                        dissect3d_api::IdempotencyKey::parse(format!("cursor-{index}")).unwrap(),
                        request.clone(),
                        fixture.request_candidate(&input, "{}", "[]").unwrap(),
                    )
                    .unwrap(),
            );
        }
        let query = JobsQuery {
            limit: Some(1),
            cursor: None,
        };
        let first = fixture
            .store
            .list_jobs(fixture.context.clone(), query)
            .unwrap();
        assert_eq!(first.items.len(), 1);
        assert!(first.truncated);
        let text = first.next_cursor.unwrap();
        assert_eq!(
            fixture
                .store
                .list_jobs(
                    fixture.context.clone(),
                    JobsQuery {
                        limit: Some(2),
                        cursor: Some(text.clone())
                    }
                )
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
        let decoded: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&text).unwrap()).unwrap();
        for (field, value, expected) in [
            (
                "client_id",
                Value::String(format!("cli_{}", "f".repeat(32))),
                ErrorCode::InvalidRequest,
            ),
            (
                "installation_id",
                Value::String(format!("ins_{}", "f".repeat(32))),
                ErrorCode::InvalidRequest,
            ),
            (
                "instance_id",
                Value::String(format!("eng_{}", "f".repeat(32))),
                ErrorCode::JobCursorExpired,
            ),
            ("high_water", Value::from(9000), ErrorCode::InvalidRequest),
            ("after_sequence", Value::from(0), ErrorCode::InvalidRequest),
            (
                "collection",
                Value::String("models".into()),
                ErrorCode::InvalidRequest,
            ),
            (
                "order",
                Value::String("descending".into()),
                ErrorCode::InvalidRequest,
            ),
        ] {
            let mut changed = decoded.clone();
            changed[field] = value;
            let cursor = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap());
            assert_eq!(
                fixture
                    .store
                    .list_jobs(
                        fixture.context.clone(),
                        JobsQuery {
                            limit: Some(1),
                            cursor: Some(cursor)
                        }
                    )
                    .unwrap_err()
                    .code,
                expected,
                "{field}"
            );
        }
        for cursor in ["!".into(), format!("{text}="), "x".repeat(1025)] {
            assert_eq!(
                fixture
                    .store
                    .list_jobs(
                        fixture.context.clone(),
                        JobsQuery {
                            limit: Some(1),
                            cursor: Some(cursor)
                        }
                    )
                    .unwrap_err()
                    .code,
                ErrorCode::InvalidRequest
            );
        }
        let show = fixture
            .store
            .show_job(fixture.context.clone(), receipts[0].job_id.clone())
            .unwrap();
        let receipt_bytes = serde_json::to_vec(&receipts[0]).unwrap().len();
        assert!(serde_json::to_vec(&show).unwrap().len() > receipt_bytes);
        let bounded = Fixture::with_policy(CorePolicy {
            control_response_bytes: receipt_bytes,
            ..CorePolicy::default()
        });
        let input = bounded.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        assert_eq!(
            bounded
                .store
                .accept_job(
                    bounded.context.clone(),
                    dissect3d_api::IdempotencyKey::parse("show-fit").unwrap(),
                    request,
                    bounded.request_candidate(&input, "{}", "[]").unwrap()
                )
                .unwrap_err()
                .code,
            ErrorCode::CapacityExceeded
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn relative_handler_timeout_never_rejects_a_live_commit() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use hyper::service::Service;
        use std::{sync::Arc, time::Duration};
        let policy = CorePolicy {
            request_timeout_ms: 100,
            ..CorePolicy::default()
        };
        let fixture = Fixture::with_policy(policy.clone());
        let input = fixture.capture(TETRAHEDRON);
        let hooks = Arc::new(crate::submission::test_support::Hooks::default());
        crate::submission::test_support::register(fixture.root.path(), &hooks);
        let server = crate::http::HttpServer::bind_with_prepared_catalog(
            &fixture.root,
            Arc::new(fixture.store),
            policy,
            Arc::new(fixture.prepared.catalog),
            fixture.prepared.readiness,
        )
        .await
        .unwrap();
        let host = server.endpoint().to_string();
        let router = server.test_router();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.run(shutdown));
        // Drive real recovery before this component-only router request. The
        // separate real-CLI test covers the absolute transport deadline.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let body = request_bytes(input.input_id.as_str(), "{}", "[]");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/jobs")
            .header("Host", host)
            .header(
                "Authorization",
                format!(
                    "Bearer {}.{}",
                    fixture.context.client_id.as_str(),
                    "42".repeat(32)
                ),
            )
            .header("Content-Type", "application/json")
            .header("Idempotency-Key", "relative-deadline")
            .body(Body::from(body))
            .unwrap();
        let (entered, release) = hooks.pause_commit();
        let service = hyper_util::service::TowerToHyperService::new(router);
        let mut response = tokio::spawn(async move { service.call(request).await.unwrap() });
        tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(250), &mut response)
                .await
                .is_err(),
            "a live commit must not be replaced by Busy"
        );
        release.send(()).unwrap();
        assert_eq!(response.await.unwrap().status(), StatusCode::CREATED);
        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    }
    #[test]
    fn dropped_acceptance_waiter_does_not_undo_committed_work() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        let key = dissect3d_api::IdempotencyKey::parse("dropped-waiter").unwrap();
        fixture.store.accept_job_without_reply(
            fixture.context.clone(),
            key.clone(),
            request.clone(),
            fixture.request_candidate(&input, "{}", "[]").unwrap(),
        );
        let replay = fixture
            .store
            .probe_job_binding(fixture.context.clone(), key, request)
            .unwrap()
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.acceptance_sequence, 1);
        assert_eq!(
            fixture
                .store
                .show_job(fixture.context.clone(), replay.job_id)
                .unwrap()
                .summary
                .state,
            dissect3d_api::JobState::Queued
        );
    }

    #[test]
    fn real_sqlite_page_exhaustion_leaves_no_partial_acceptance_or_sequence_gap() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        fixture
            .store
            .limit_database_pages_to_current_plus_one()
            .unwrap();
        let mut committed = 0i64;
        let mut exhausted = false;
        for index in 0..128 {
            let key =
                dissect3d_api::IdempotencyKey::parse(format!("sqlite-pages-{index}")).unwrap();
            match fixture.store.accept_job(
                fixture.context.clone(),
                key.clone(),
                request.clone(),
                fixture.request_candidate(&input, "{}", "[]").unwrap(),
            ) {
                Ok(receipt) => {
                    committed += 1;
                    assert_eq!(receipt.acceptance_sequence, committed);
                }
                Err(error) => {
                    assert_eq!(error.code, dissect3d_api::ErrorCode::StoreUnavailable);
                    assert!(
                        fixture
                            .store
                            .probe_job_binding(fixture.context.clone(), key, request.clone())
                            .unwrap()
                            .is_none()
                    );
                    exhausted = true;
                    break;
                }
            }
        }
        assert!(
            exhausted,
            "exercise SQLite page exhaustion before queue limit"
        );
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                committed
            );
        }
        assert_eq!(
            db.query_row("SELECT value FROM job_sequence", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            committed
        );
    }

    #[test]
    fn conflicting_candidate_race_commits_only_the_winning_equivalence_class() {
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let candidates: Vec<_> = (0..4)
            .map(|index| {
                let parameters = if index % 2 == 0 {
                    "{}"
                } else {
                    "{\"fail_execution\":true}"
                };
                (
                    decode_job_request(&request_bytes(input.input_id.as_str(), parameters, "[]"))
                        .unwrap(),
                    fixture.request_candidate(&input, parameters, "[]").unwrap(),
                )
            })
            .collect();
        let barrier = std::sync::Barrier::new(4);
        let results = std::thread::scope(|scope| {
            let threads: Vec<_> = candidates
                .into_iter()
                .map(|(request, candidate)| {
                    let (barrier, store, auth) =
                        (&barrier, &fixture.store, fixture.context.clone());
                    scope.spawn(move || {
                        barrier.wait();
                        store.accept_job(
                            auth,
                            dissect3d_api::IdempotencyKey::parse("conflicting-race").unwrap(),
                            request,
                            candidate,
                        )
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        let receipts: Vec<_> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .collect();
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            receipts.iter().filter(|receipt| !receipt.replayed).count(),
            1
        );
        assert_eq!(receipts[0].job_id, receipts[1].job_id);
        assert_eq!(receipts[0].resolved, receipts[1].resolved);
        assert_eq!(results.iter().filter(|result|matches!(result,Err(error) if error.code==dissect3d_api::ErrorCode::IdempotencyConflict)).count(),2);
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
    }
    #[test]
    fn private_reduced_limits_exercise_each_authoritative_capacity_boundary() {
        use crate::store::submission::AcceptanceLimits;
        use dissect3d_api::{ErrorCode, IdempotencyKey};
        for boundary in ["queue", "bindings", "captured", "metadata", "free"] {
            let fixture = Fixture::new();
            let a = fixture.capture(TETRAHEDRON);
            let b = fixture.capture(TETRAHEDRON);
            let request =
                decode_job_request(&request_bytes(a.input_id.as_str(), "{}", "[]")).unwrap();
            let key = IdempotencyKey::parse("limits-original").unwrap();
            let first = fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    key.clone(),
                    request.clone(),
                    fixture.request_candidate(&a, "{}", "[]").unwrap(),
                )
                .unwrap();
            let mut limits = AcceptanceLimits::default();
            match boundary {
                "queue" => limits.queued = 1,
                "bindings" => limits.bindings = 1,
                "captured" => limits.captured_bytes = a.byte_length,
                "metadata" => limits.metadata_bytes = 1,
                _ => limits.free_reserve = u64::MAX,
            };
            fixture.store.set_test_job_limits(limits);
            let replacement =
                decode_job_request(&request_bytes(b.input_id.as_str(), "{}", "[]")).unwrap();
            let rejected = fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    IdempotencyKey::parse("limits-new").unwrap(),
                    replacement,
                    fixture.request_candidate(&b, "{}", "[]").unwrap(),
                )
                .unwrap_err();
            assert_eq!(rejected.code, ErrorCode::CapacityExceeded, "{boundary}");
            let replay = fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    key,
                    request,
                    fixture.request_candidate(&a, "{}", "[]").unwrap(),
                )
                .unwrap();
            assert!(replay.replayed);
            assert_eq!(replay.job_id, first.job_id, "{boundary}");
            let db =
                rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
            for table in [
                "jobs",
                "job_inputs",
                "job_acceptance_events",
                "submission_bindings",
            ] {
                assert_eq!(
                    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                        .unwrap(),
                    1,
                    "{boundary} {table}"
                );
            }
        }
    }
    async fn component_request(
        router: axum::Router,
        host: &str,
        method: &str,
        path: &str,
        body: Vec<u8>,
        key: Option<&str>,
    ) -> axum::response::Response {
        use hyper::service::Service;
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("Host", host)
            .header(
                "Authorization",
                format!(
                    "Bearer cli_2223456789abcdef0123456789abcdef.{}",
                    "42".repeat(32)
                ),
            )
            .header("Content-Type", "application/json");
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        hyper_util::service::TowerToHyperService::new(router)
            .call(request.body(axum::body::Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_fresh_validation_reprobes_a_competing_committed_binding() {
        use dissect3d_api::IdempotencyKey;
        use std::{sync::Arc, time::Duration};
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let body = request_bytes(input.input_id.as_str(), "{}", "[]");
        let request = decode_job_request(&body).unwrap();
        let hooks = Arc::new(crate::submission::test_support::Hooks::default());
        crate::submission::test_support::register(fixture.root.path(), &hooks);
        let store = Arc::new(fixture.store);
        let server = crate::http::HttpServer::bind_with_prepared_catalog(
            &fixture.root,
            store.clone(),
            CorePolicy::default(),
            Arc::new(fixture.prepared.catalog),
            fixture.prepared.readiness,
        )
        .await
        .unwrap();
        let host = server.endpoint().to_string();
        let router = server.test_router();
        let (inputs, jobs) = server.test_recovery_states();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.run(shutdown));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !inputs.is_reconciled() || !jobs.is_reconciled() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let (entered, commit) = hooks.pause_commit();
        let first_router = router.clone();
        let first_host = host.clone();
        let first_body = body.clone();
        let first = tokio::spawn(async move {
            component_request(
                first_router,
                &first_host,
                "POST",
                "/v1/jobs",
                first_body,
                Some("competing-winner"),
            )
            .await
        });
        tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        // Deliberate fixture damage after the first validator finished. The
        // second fresh validator fails; it must still honor committed authority.
        std::fs::write(
            fixture
                .root
                .path()
                .join(format!("inputs/data/{}.bin", input.input_id.as_str())),
            b"damaged fixture input",
        )
        .unwrap();
        let (failed, resume) = hooks.pause_failure();
        let second_router = router.clone();
        let second_host = host.clone();
        let second = tokio::spawn(async move {
            component_request(
                second_router,
                &second_host,
                "POST",
                "/v1/jobs",
                body,
                Some("competing-winner"),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), failed)
            .await
            .unwrap()
            .unwrap();
        commit.send(()).unwrap();
        let key = IdempotencyKey::parse("competing-winner").unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let winner = loop {
            let (store, auth, key, request) = (
                store.clone(),
                fixture.context.clone(),
                key.clone(),
                request.clone(),
            );
            if let Some(receipt) =
                tokio::task::spawn_blocking(move || store.probe_job_binding(auth, key, request))
                    .await
                    .unwrap()
                    .unwrap()
            {
                break receipt;
            }
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        resume.send(()).unwrap();
        let response = second.await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let receipt: dissect3d_api::AcceptanceReceipt = dissect3d_api::decode_submission_json(
            &axum::body::to_bytes(response.into_body(), 262_144)
                .await
                .unwrap(),
            262_144,
        )
        .unwrap();
        assert!(receipt.replayed);
        assert_eq!(receipt.job_id, winner.job_id);
        assert_eq!(receipt.resolved, winner.resolved);
        let db = rusqlite::Connection::open(fixture.root.path().join("metadata.sqlite3")).unwrap();
        for table in [
            "jobs",
            "job_inputs",
            "job_acceptance_events",
            "submission_bindings",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        drop(db);
        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn referenced_file_audit_preserves_control_and_replay_while_fresh_work_waits() {
        use std::{sync::Arc, time::Duration};
        let fixture = Fixture::new();
        let input = fixture.capture(TETRAHEDRON);
        let body = request_bytes(input.input_id.as_str(), "{}", "[]");
        let accepted = fixture
            .store
            .accept_job(
                fixture.context.clone(),
                dissect3d_api::IdempotencyKey::parse("recovery-owned").unwrap(),
                decode_job_request(&body).unwrap(),
                fixture.request_candidate(&input, "{}", "[]").unwrap(),
            )
            .unwrap();
        let hooks = Arc::new(crate::submission::test_support::Hooks::default());
        crate::submission::test_support::register(fixture.root.path(), &hooks);
        let (entered, release) = hooks.pause_audit();
        let server = crate::http::HttpServer::bind_with_prepared_catalog(
            &fixture.root,
            Arc::new(fixture.store),
            CorePolicy::default(),
            Arc::new(fixture.prepared.catalog),
            fixture.prepared.readiness,
        )
        .await
        .unwrap();
        let host = server.endpoint().to_string();
        let router = server.test_router();
        let (_, jobs) = server.test_recovery_states();
        let (stop, shutdown) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.run(shutdown));
        tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert!(!jobs.is_reconciled());
        for path in ["/v1/info", "/v1/auth/status", "/v1/jobs"] {
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                component_request(router.clone(), &host, "GET", path, Vec::new(), None),
            )
            .await
            .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK, "{path}");
        }
        let path = format!("/v1/jobs/{}", accepted.job_id.as_str());
        assert_eq!(
            component_request(router.clone(), &host, "GET", &path, Vec::new(), None)
                .await
                .status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let fresh = component_request(
            router.clone(),
            &host,
            "POST",
            "/v1/jobs",
            body.clone(),
            Some("recovery-fresh"),
        )
        .await;
        assert_eq!(fresh.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let error: Value = serde_json::from_slice(
            &axum::body::to_bytes(fresh.into_body(), 262_144)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(error["error"]["code"], "engine_recovering");
        let replay = component_request(
            router.clone(),
            &host,
            "POST",
            "/v1/jobs",
            body,
            Some("recovery-owned"),
        )
        .await;
        assert_eq!(replay.status(), axum::http::StatusCode::OK);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !jobs.is_reconciled() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            component_request(router, &host, "GET", &path, Vec::new(), None)
                .await
                .status(),
            axum::http::StatusCode::OK
        );
        stop.send(()).unwrap();
        serving.await.unwrap().unwrap();
    }
    #[test]
    fn job_pages_reduce_item_count_to_the_effective_byte_budget_without_skipping() {
        use dissect3d_api::{IdempotencyKey, JobsQuery};
        let limit = 16_384;
        let fixture = Fixture::with_policy(CorePolicy {
            control_response_bytes: limit,
            ..CorePolicy::default()
        });
        let input = fixture.capture(TETRAHEDRON);
        let request =
            decode_job_request(&request_bytes(input.input_id.as_str(), "{}", "[]")).unwrap();
        for index in 0..128 {
            fixture
                .store
                .accept_job(
                    fixture.context.clone(),
                    IdempotencyKey::parse(format!("byte-page-{index}")).unwrap(),
                    request.clone(),
                    fixture.request_candidate(&input, "{}", "[]").unwrap(),
                )
                .unwrap();
        }
        let mut cursor = None;
        let mut sequences = Vec::new();
        loop {
            let page = fixture
                .store
                .list_jobs(
                    fixture.context.clone(),
                    JobsQuery {
                        limit: Some(100),
                        cursor,
                    },
                )
                .unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() <= limit);
            assert!(!page.items.is_empty());
            if sequences.is_empty() {
                assert!(
                    page.items.len() < 100,
                    "byte packing must reduce the first page below the requested item limit"
                );
            }
            for item in page.items {
                sequences.push(item.acceptance_sequence);
            }
            assert_eq!(page.truncated, page.next_cursor.is_some());
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
            assert!(sequences.len() < 128, "continuation must advance");
        }
        assert_eq!(sequences, (1..=128).collect::<Vec<i64>>());
    }
}
