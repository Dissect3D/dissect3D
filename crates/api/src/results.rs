//! Closed complete-only mesh-copy interpretation. This is not publication authority.
use crate::{InputIdentity, JobId, ResolvedJob, SubmissionDecodeError, SubmissionValue};
use serde::{Deserialize, Serialize};

pub const RESULT_FEATURE: &str = "result_publication.rp-0.1";
pub const MANIFEST_BYTES_MAX: usize = 262_144;
pub fn copy_identity_transform() -> [crate::DeclarationValue; 16] {
    [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1].map(crate::DeclarationValue::from)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultManifest {
    pub manifest_version: String,
    pub required_features: Vec<String>,
    pub result_id: String,
    pub job_id: JobId,
    pub attempt_id: String,
    pub publication_id: String,
    pub published_at_ms: u64,
    pub files: Vec<ResultFile>,
    pub components: Vec<ResultComponent>,
    pub assembly: ResultAssembly,
    pub coordinates: ResultCoordinates,
    pub materials: ResultMaterials,
    pub provenance: ResultProvenance,
    pub validation: ResultValidation,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultFile {
    pub artifact_id: String,
    pub filename: String,
    pub role: String,
    pub format: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: crate::ContentDigest,
    pub mandatory: bool,
    pub availability: String,
    pub fidelity: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultComponent {
    pub component_id: String,
    pub artifact_ids: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub parent_id: Option<String>,
    pub status: String,
    pub local_transform: [crate::DeclarationValue; 16],
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultAssembly {
    pub matrix_storage: String,
    pub vectors: String,
    pub composition: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultCoordinates {
    pub axes: String,
    pub handedness: String,
    pub units: String,
    pub scale_assumption: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMaterials {
    pub status: String,
    pub artifact_ids: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultProvenance {
    pub resolved: ResolvedJob,
    pub input_identities: Vec<InputIdentity>,
    #[serde(deserialize_with = "required_nullable")]
    pub effective_seed: Option<SubmissionValue>,
    pub transformations: Vec<String>,
    pub reproducibility_limits: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultValidation {
    pub validator_id: String,
    pub validator_revision: String,
    pub policy: String,
    pub geometry_valid: bool,
    pub copy_fidelity: bool,
    pub partial: bool,
    pub missing_components: Vec<String>,
    pub findings: Vec<ResultFinding>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultFinding {
    pub severity: String,
    pub code: String,
}
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(d)
}
fn invalid() -> SubmissionDecodeError {
    SubmissionDecodeError::InvalidRequest
}
fn id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|v| {
        v.len() == 32
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.chars().count() <= max
}

/// Portable one-component ASCII name, including Windows device/ADS aliases.
pub fn validate_result_filename(name: &str) -> Result<(), SubmissionDecodeError> {
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name.ends_with('.')
        || name.eq_ignore_ascii_case("manifest.json")
    {
        return Err(invalid());
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CLOCK$"].contains(&stem.as_str())
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
    {
        return Err(invalid());
    }
    Ok(())
}

/// Decode once with duplicate-key/depth/byte bounds and semantic interpretation.
pub fn decode_result_manifest(bytes: &[u8]) -> Result<ResultManifest, SubmissionDecodeError> {
    let manifest: ResultManifest = crate::decode_submission_json(bytes, MANIFEST_BYTES_MAX)?;
    manifest.validate()?;
    // ResolvedJob is a legacy wire type. Reject any ignored extension fields here
    // without weakening or changing the queued-only decoder's compatibility policy.
    let raw: SubmissionValue = crate::decode_submission_json(bytes, MANIFEST_BYTES_MAX)?;
    let canonical: SubmissionValue = crate::decode_submission_json(
        &serde_json::to_vec(&manifest).map_err(|_| invalid())?,
        MANIFEST_BYTES_MAX,
    )?;
    if !same_shape(&raw, &canonical) {
        return Err(invalid());
    }
    Ok(manifest)
}
fn same_shape(a: &SubmissionValue, b: &SubmissionValue) -> bool {
    match (a, b) {
        (SubmissionValue::Object(a), SubmissionValue::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| same_shape(v, w)))
        }
        (SubmissionValue::Array(a), SubmissionValue::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_shape(a, b))
        }
        _ => true,
    }
}
impl ResultManifest {
    pub fn validate(&self) -> Result<(), SubmissionDecodeError> {
        self.provenance.resolved.validate().map_err(|_| invalid())?;
        if self.manifest_version != "1.0"
            || self.required_features != [RESULT_FEATURE]
            || !id(&self.result_id, "res_")
            || !id(&self.attempt_id, "att_")
            || !id(&self.publication_id, "pub_")
            || self.files.len() != 1
            || self.components.len() != 1
        {
            return Err(invalid());
        }
        let file = &self.files[0];
        let component = &self.components[0];
        validate_result_filename(&file.filename)?;
        if !id(&file.artifact_id, "art_")
            || file.role != "mesh"
            || file.format != "obj"
            || file.media_type != "application/octet-stream"
            || !(1..=1_048_576).contains(&file.byte_length)
            || !file.mandatory
            || file.availability != "available"
            || file.fidelity != "byte_preserving_copy"
            || !bounded(&component.component_id, 64)
            || component.artifact_ids != [file.artifact_id.clone()]
            || component.parent_id.is_some()
            || component.status != "valid"
            || component
                .local_transform
                .iter()
                .zip(copy_identity_transform())
                .any(|(a, b)| {
                    a.as_number()
                        .zip(b.as_number())
                        .is_none_or(|(a, b)| a.compare(b) != Some(std::cmp::Ordering::Equal))
                })
            || self.assembly.matrix_storage != "column_major"
            || self.assembly.vectors != "column"
            || self.assembly.composition != "parent_world_times_local"
            || [
                &self.coordinates.axes,
                &self.coordinates.handedness,
                &self.coordinates.units,
                &self.coordinates.scale_assumption,
            ]
            .iter()
            .any(|v| v.as_str() != "unknown")
            || !["none", "unknown"].contains(&self.materials.status.as_str())
            || !self.materials.artifact_ids.is_empty()
        {
            return Err(invalid());
        }
        let p = &self.provenance;
        if p.input_identities.len() != 1
            || p.effective_seed.is_some()
            || !p.transformations.is_empty()
            || p.reproducibility_limits.is_empty()
            || p.reproducibility_limits.len() > 16
            || p.reproducibility_limits.iter().any(|s| !bounded(s, 1024))
        {
            return Err(invalid());
        }
        let input = &p.input_identities[0];
        if p.resolved.selection.task.id != "dissect3d.test.mesh-copy"
            || p.resolved.selection.task.version != "1.0"
            || input.media_type != "application/octet-stream"
            || p.resolved.inputs.len() != 1
            || p.resolved.inputs.get("mesh") != Some(&p.input_identities)
            || input.byte_length != file.byte_length
            || input.sha256 != file.sha256
        {
            return Err(invalid());
        }
        let v = &self.validation;
        if v.validator_id != "dissect3d.test.validator"
            || !bounded(&v.validator_revision, 128)
            || v.policy != "positive-index-triangular-obj-v1"
            || !v.geometry_valid
            || !v.copy_fidelity
            || v.partial
            || !v.missing_components.is_empty()
            || v.findings.len() > 64
            || v.findings.iter().any(|f| {
                !["info", "warning"].contains(&f.severity.as_str()) || !bounded(&f.code, 128)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}

mod read;
pub use read::*;
