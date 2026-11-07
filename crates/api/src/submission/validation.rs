//! Pure validation shared by network receipts and protected local records.

const MAX_INPUT_BYTES: u64 = 268_435_456;

fn valid_resolved_job(resolved: &crate::ResolvedJob) -> bool {
    let selection = &resolved.selection;
    if !valid_public_id(&selection.support_id, "mdl_")
        || !valid_digest(&selection.support_sha256)
        || !valid_public_id(&selection.task_binding_id, "tsk_")
        || !valid_public_id(&selection.runtime_id, "rtp_")
        || !valid_digest(&selection.runtime_sha256)
        || selection.support_ref.is_empty()
        || selection.runtime_ref.is_empty()
        || selection.variant.is_empty()
        || selection.task.id.is_empty()
        || !valid_wire_task_version(&selection.task.version)
        || !nonempty(&selection.code.upstream_repository)
        || !nonempty(&selection.code.upstream_revision)
        || !nonempty(&selection.code.executed_repository)
        || !nonempty(&selection.code.executed_revision)
        || !nonempty(&selection.code.build_provenance)
        || selection
            .code
            .patches
            .iter()
            .any(|patch| !nonempty(&patch.id) || !valid_digest(&patch.sha256))
        || !nonempty(&selection.adapter.id)
        || !nonempty(&selection.adapter.revision)
        || !valid_digest(&selection.adapter.sha256)
        || !nonempty(&selection.adapter.interface_version)
        || selection.assets.iter().any(|asset| {
            !nonempty(&asset.id)
                || !nonempty(&asset.kind)
                || !nonempty(&asset.source)
                || !nonempty(&asset.revision)
                || !valid_digest(&asset.sha256)
                || asset.byte_length == 0
                || !nonempty(&asset.rights_id)
        })
        || selection.schemas.iter().any(|schema| {
            !nonempty(&schema.id) || !nonempty(&schema.version) || !valid_digest(&schema.sha256)
        })
        || resolved.readiness.check_id.is_empty()
        || resolved.readiness.runtime_realization.is_empty()
        || resolved.validation.is_empty()
        || resolved
            .validation
            .iter()
            .any(|evidence| evidence.status != "passed")
        || resolved.evidence_scope.is_empty()
        || resolved.evidence_scope.len() > 128
    {
        return false;
    }
    if resolved.inputs.is_empty() || resolved.inputs.len() > 16 {
        return false;
    }
    let mut occurrences = 0_usize;
    let mut total_bytes = 0_u64;
    for (role, inputs) in &resolved.inputs {
        if !valid_input_role(role) || inputs.is_empty() {
            return false;
        }
        occurrences += inputs.len();
        if occurrences > 64 {
            return false;
        }
        for input in inputs {
            if input.byte_length == 0
                || input.byte_length > MAX_INPUT_BYTES
                || !valid_media_type(&input.media_type)
            {
                return false;
            }
            total_bytes = match total_bytes.checked_add(input.byte_length) {
                Some(total) if total <= 1_073_741_824 => total,
                _ => return false,
            };
        }
    }
    true
}

fn valid_input_role(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_wire_task_version(value: &str) -> bool {
    value.len() <= 32
        && value.is_ascii()
        && matches!(value.split_once('.'), Some((major, minor))
            if !major.is_empty()
                && !minor.is_empty()
                && major.bytes().all(|byte| byte.is_ascii_digit())
                && minor.bytes().all(|byte| byte.is_ascii_digit())
                && !minor.contains('.'))
}

fn nonempty(value: &str) -> bool {
    !value.is_empty()
}

pub(crate) fn valid_media_type(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    let allowed = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_alphabetic() || byte.is_ascii_digit() || b"!#$&^_.+-".contains(&byte)
            })
    };
    allowed(kind) && allowed(subtype) && !subtype.contains('/')
}

pub(crate) fn valid_public_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl super::ResolvedJob {
    /// Apply the same structural and provenance checks to network and local data.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if valid_resolved_job(self) {
            Ok(())
        } else {
            Err(crate::ValidationError)
        }
    }
}

impl super::AcceptanceReceipt {
    /// Validate a queued acceptance independently of its transport status code.
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.api_version != "1.0"
            || !self.accepted
            || self.acceptance_sequence < 1
            || self.snapshot_revision != 1
        {
            return Err(crate::ValidationError);
        }
        self.resolved.validate()
    }
}
