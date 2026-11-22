//! Engine-controlled capture of a closed candidate (RP-P02/3; ENG-045/048).
//!
//! The only producers of `ClosedCandidate` and `VerifiedInputSet`. Capture
//! needs the supervisor's `CleanupEvidence` for this attempt's session, so it
//! cannot run while any member of the worker tree may still write. Worker
//! reports are claims: names are checked as portable single components and
//! must match the retained staging folder's listing exactly; lengths and
//! digests are recomputed from the bytes read through verified handles and
//! must equal the report. Nothing here reopens a checked path, reads a worker
//! path, or mutates the captured input snapshot. Inactive until RP-P03/WE-P06.
use super::{CandidateFileRef, ClosedCandidate, PublicationError, VerifiedInputSet, digest_hex};
use crate::store::cleanup::CleanupEvidence;
use crate::store::execution::DispatchRecord;
use crate::submission::obj::MAX_BYTES;
use crate::worker_protocol::CandidateReport;
use dissect3d_api::{InputIdentity, validate_result_filename};
use dissect3d_platform::{AttemptRoot, PlatformError, PrivateInputReader, RelativePath};
use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bound on the worker's output description, which is captured to close the
/// folder but never trusted for mesh-copy semantics.
pub(super) const DESCRIPTION_BYTES_MAX: u64 = 65_536;
/// Candidate files one report may name (worker schema maxItems).
const CANDIDATE_FILES_MAX: usize = 16;
/// Capture shares validation's per-candidate time bound.
const CAPTURE_BUDGET: Duration = Duration::from_millis(5_000);

fn refused(error: PlatformError) -> PublicationError {
    match error {
        PlatformError::Io | PlatformError::Busy | PlatformError::UnsupportedRoot => {
            PublicationError::Storage
        }
        _ => PublicationError::InvalidCandidate,
    }
}

fn portable(name: &str) -> Result<RelativePath, PublicationError> {
    validate_result_filename(name).map_err(|_| PublicationError::InvalidCandidate)?;
    RelativePath::parse(name).map_err(|_| PublicationError::InvalidCandidate)
}

/// Capture the candidate `report` names from `staging`, after `cleanup`
/// confirmed the attempt's whole worker tree terminated.
pub(super) fn capture_candidate(
    dispatch: &DispatchRecord,
    report: &CandidateReport,
    cleanup: &CleanupEvidence,
    staging: &AttemptRoot,
) -> Result<ClosedCandidate, PublicationError> {
    let deadline = Instant::now() + CAPTURE_BUDGET;
    // The witness must be for this attempt's session, not any finished tree.
    if crate::store::launch_identity::session_nonce(&dispatch.session_id)
        != Some(cleanup.identity().session_nonce)
    {
        return Err(PublicationError::InvalidCandidate);
    }
    if report.files.is_empty() || report.files.len() > CANDIDATE_FILES_MAX {
        return Err(PublicationError::InvalidCandidate);
    }
    let files = report
        .files
        .iter()
        .map(|file| portable(&file.relative_name))
        .collect::<Result<Vec<_>, _>>()?;
    let description = portable(&report.description_handle)?;
    let mut expected = files.clone();
    expected.push(description.clone());
    // Duplicates and case aliases among reported names are refused by
    // close_entries; anything else in the folder refuses the candidate too.
    let closed = staging.close_entries(&expected).map_err(refused)?;
    let mut captured = Vec::with_capacity(files.len());
    for (name, claim) in files.iter().zip(&report.files) {
        if Instant::now() >= deadline {
            return Err(PublicationError::Deadline);
        }
        let artifact = closed
            .capture_candidate(name, MAX_BYTES as u64)
            .map_err(refused)?;
        let bytes: Arc<[u8]> = Arc::from(artifact.into_bytes());
        if bytes.len() as u64 != claim.byte_length || digest_hex(&bytes, deadline)? != claim.sha256
        {
            return Err(PublicationError::InvalidCandidate);
        }
        captured.push(CandidateFileRef {
            filename: name.as_str().to_owned(),
            bytes,
        });
    }
    closed
        .capture_candidate(&description, DESCRIPTION_BYTES_MAX)
        .map_err(refused)?;
    if Instant::now() >= deadline {
        return Err(PublicationError::Deadline);
    }
    Ok(ClosedCandidate {
        job_id: dispatch.job_id.clone(),
        attempt_id: dispatch.attempt_id.clone(),
        session_id: dispatch.session_id.clone(),
        files: captured,
    })
}

/// Read one captured input snapshot through `reader`, which the caller must
/// open freshly with `OwnedRoot::open_immutable_input` (a reader handed to a
/// worker shares its file offset on Unix). Length and digest must equal the
/// stored identity.
pub(super) fn verified_input(
    identity: InputIdentity,
    reader: PrivateInputReader,
) -> Result<VerifiedInputSet, PublicationError> {
    let deadline = Instant::now() + CAPTURE_BUDGET;
    let mut bytes = Vec::new();
    reader
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PublicationError::Storage)?;
    if bytes.len() > MAX_BYTES
        || bytes.len() as u64 != identity.byte_length
        || digest_hex(&bytes, deadline)? != identity.sha256.as_str()
    {
        return Err(PublicationError::InputIntegrity);
    }
    Ok(VerifiedInputSet {
        identities: vec![identity],
        bytes: Arc::from(bytes),
    })
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
