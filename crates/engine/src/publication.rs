//! Independent bounded validation of immutable captured candidate content.
//! RP-P02 supplies the native capture/cleanup producer; no public route uses this yet.
use crate::store::execution::DispatchRecord;
use crate::submission::obj::{MAX_BYTES, ObjError, parse_obj_until};
use dissect3d_api::*;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

const VALIDATION_BUDGET: Duration = Duration::from_millis(5_000);
static OUTPUT_SLOT: AtomicBool = AtomicBool::new(false);
struct ValidationSlot;
impl ValidationSlot {
    fn acquire() -> Result<Self, PublicationError> {
        OUTPUT_SLOT
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| PublicationError::Busy)?;
        Ok(Self)
    }
}
impl Drop for ValidationSlot {
    fn drop(&mut self) {
        OUTPUT_SLOT.store(false, Ordering::Release);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationError {
    Busy,
    Deadline,
    InvalidCandidate,
    InvalidGeometry,
    InputIntegrity,
    CopyFidelity,
    InvalidManifest,
    Limit,
}

// Constructors stay in this module: neither a worker nor another caller can
// supply a validated witness. RP-P02 must establish native confinement/closure
// before adding the production immutable-capture constructor.
pub(crate) struct CandidateFileRef {
    filename: String,
    bytes: Arc<[u8]>,
}
pub(crate) struct ClosedCandidate {
    job_id: JobId,
    attempt_id: String,
    session_id: String,
    files: Vec<CandidateFileRef>,
}
pub(crate) struct VerifiedInputSet {
    identities: Vec<InputIdentity>,
    bytes: Arc<[u8]>,
}
pub(crate) struct ValidatedCandidate {
    job_id: JobId,
    attempt_id: String,
    filename: String,
    bytes: Arc<[u8]>,
    resolved: ResolvedJob,
    input: InputIdentity,
}
pub(crate) struct ManifestBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: [u8; 32],
}
fn budget(deadline: Instant) -> Result<(), PublicationError> {
    if Instant::now() >= deadline {
        Err(PublicationError::Deadline)
    } else {
        Ok(())
    }
}
fn digest(bytes: &[u8], deadline: Instant) -> Result<[u8; 32], PublicationError> {
    let mut hash = Sha256::new();
    for turn in bytes.chunks(65_536) {
        budget(deadline)?;
        hash.update(turn);
    }
    budget(deadline)?;
    Ok(hash.finalize().into())
}
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn validate_candidate(
    dispatch: &DispatchRecord,
    candidate: &ClosedCandidate,
    inputs: &VerifiedInputSet,
) -> Result<ValidatedCandidate, PublicationError> {
    validate_candidate_until(
        dispatch,
        candidate,
        inputs,
        Instant::now() + VALIDATION_BUDGET,
    )
}
fn validate_candidate_until(
    dispatch: &DispatchRecord,
    candidate: &ClosedCandidate,
    inputs: &VerifiedInputSet,
    deadline: Instant,
) -> Result<ValidatedCandidate, PublicationError> {
    let _slot = ValidationSlot::acquire()?;
    budget(deadline)?;
    if dispatch.timing.expired() {
        return Err(PublicationError::Deadline);
    }
    if candidate.job_id != dispatch.job_id
        || candidate.attempt_id != dispatch.attempt_id
        || candidate.session_id != dispatch.session_id
        || candidate.files.len() != 1
        || inputs.identities.len() != 1
    {
        return Err(PublicationError::InvalidCandidate);
    }
    let file = &candidate.files[0];
    let input = &inputs.identities[0];
    validate_result_filename(&file.filename).map_err(|_| PublicationError::InvalidCandidate)?;
    if file.bytes.is_empty()
        || file.bytes.len() > MAX_BYTES
        || inputs.bytes.is_empty()
        || inputs.bytes.len() > MAX_BYTES
        || dispatch.resolved_json.len() > MANIFEST_BYTES_MAX
    {
        return Err(PublicationError::Limit);
    }
    let resolved: ResolvedJob =
        decode_submission_json(dispatch.resolved_json.as_bytes(), MANIFEST_BYTES_MAX)
            .map_err(|_| PublicationError::InvalidCandidate)?;
    resolved
        .validate()
        .map_err(|_| PublicationError::InvalidCandidate)?;
    if resolved.selection.task.id != "dissect3d.test.mesh-copy"
        || resolved.selection.task.version != "1.0"
        || resolved.inputs.len() != 1
        || resolved.inputs.get("mesh") != Some(&inputs.identities)
    {
        return Err(PublicationError::InvalidCandidate);
    }
    if input.media_type != "application/octet-stream"
        || input.byte_length != inputs.bytes.len() as u64
        || input.sha256.as_str() != hex(digest(&inputs.bytes, deadline)?)
    {
        return Err(PublicationError::InputIntegrity);
    }
    parse_obj_until(file.bytes.as_ref(), deadline).map_err(|e| {
        if e == ObjError::Deadline {
            PublicationError::Deadline
        } else {
            PublicationError::InvalidGeometry
        }
    })?;
    if file.bytes.as_ref() != inputs.bytes.as_ref()
        || input.sha256.as_str() != hex(digest(&file.bytes, deadline)?)
    {
        return Err(PublicationError::CopyFidelity);
    }
    budget(deadline)?;
    if dispatch.timing.expired() {
        return Err(PublicationError::Deadline);
    }
    Ok(ValidatedCandidate {
        job_id: dispatch.job_id.clone(),
        attempt_id: dispatch.attempt_id.clone(),
        filename: file.filename.clone(),
        bytes: file.bytes.clone(),
        resolved,
        input: input.clone(),
    })
}
impl ValidatedCandidate {
    pub(crate) fn manifest(
        &self,
        result_id: &str,
        publication_id: &str,
        artifact_id: &str,
        published_at_ms: u64,
    ) -> Result<ManifestBytes, PublicationError> {
        let m = ResultManifest {
            manifest_version: "1.0".into(),
            required_features: vec![RESULT_FEATURE.into()],
            result_id: result_id.into(),
            job_id: self.job_id.clone(),
            attempt_id: self.attempt_id.clone(),
            publication_id: publication_id.into(),
            published_at_ms,
            files: vec![ResultFile {
                artifact_id: artifact_id.into(),
                filename: self.filename.clone(),
                role: "mesh".into(),
                format: "obj".into(),
                media_type: "application/octet-stream".into(),
                byte_length: self.bytes.len() as u64,
                sha256: self.input.sha256.clone(),
                mandatory: true,
                availability: "available".into(),
                fidelity: "byte_preserving_copy".into(),
            }],
            components: vec![ResultComponent {
                component_id: "mesh".into(),
                artifact_ids: vec![artifact_id.into()],
                parent_id: None,
                status: "valid".into(),
                local_transform: copy_identity_transform(),
            }],
            assembly: ResultAssembly {
                matrix_storage: "column_major".into(),
                vectors: "column".into(),
                composition: "parent_world_times_local".into(),
            },
            coordinates: ResultCoordinates {
                axes: "unknown".into(),
                handedness: "unknown".into(),
                units: "unknown".into(),
                scale_assumption: "unknown".into(),
            },
            materials: ResultMaterials {status: "none".into(), artifact_ids: vec![]},
            provenance: ResultProvenance {
                resolved: self.resolved.clone(),
                input_identities: vec![self.input.clone()],
                effective_seed: None,
                transformations: vec![],
                reproducibility_limits: vec!["Controlled byte-preserving copy only; no inference or determinism guarantee for future adapters.".into()],
            },
            validation: ResultValidation {
                validator_id: "dissect3d.test.validator".into(),
                validator_revision: "1".into(),
                policy: "positive-index-triangular-obj-v1".into(),
                geometry_valid: true,
                copy_fidelity: true,
                partial: false,
                missing_components: vec![],
                findings: vec![],
            },
        };
        m.validate()
            .map_err(|_| PublicationError::InvalidManifest)?;
        let bytes = serde_json::to_vec(&m).map_err(|_| PublicationError::InvalidManifest)?;
        if bytes.len() > MANIFEST_BYTES_MAX {
            return Err(PublicationError::Limit);
        }
        let sha256 = Sha256::digest(&bytes).into();
        Ok(ManifestBytes { bytes, sha256 })
    }
}
#[cfg(test)]
#[path = "publication_tests.rs"]
mod tests;
