//! Durable private preparation, reclamation and reconciliation of result
//! files (RP-P02/4-/6; ENG-045/046, RP-003, RP-005 accounting).
//!
//! Order for one validated candidate: allocate result, publication and
//! artifact identities; build the canonical manifest; record identities, exact
//! file rows and the charge in one Store transaction; then write each file
//! through the platform's durable protocol and re-read it through a fresh
//! no-follow handle to recompute its length and digest. Only after every file
//! passes does the Store mark the allocation `prepared` and a sealed
//! `PreparedPublication` exist. Prepared files sit under engine-generated
//! names in `results/objects`, never in a worker's staging folder, and stay
//! private until RP-P03 commits a `results` row.
//!
//! A failure after the reservation leaves the charge and any written name in
//! place and, once this call's native work has returned, records the
//! allocation `failed`. Reclamation removes content only once the Store
//! records the job as terminal without a result and no preparer can still be
//! writing (`prepared`/`failed`, or `preparing` from an earlier session), so
//! neither a timeout nor a lost caller can free space or delete content (adapted from the reference-aware input recovery
//! here, and from ollama's blob store which keeps digest-named files until no
//! manifest references them). Durable deletion always precedes charge release.
//!
//! Where the root fails its durable mutation check (an unsupported filesystem
//! or sync root, or a root renamed/replaced since open) every operation
//! refuses before charging or writing anything. Windows uses the DS-G04
//! namespace-durability protocol (decision 2026-11-23); physical power-loss
//! evidence remains a separate open gate on every target.
use super::{ManifestBytes, PublicationError, ValidatedCandidate, budget, digest};
use crate::CoreError;
use crate::store::results::{
    FileRole, PublicationReservation, ReclaimBatch, ReservedFile, generated_name,
};
use dissect3d_api::JobId;
use dissect3d_platform::{DurableArtifact, OwnedInputScan, OwnedRoot, PlatformError, RelativePath};
use std::io::Read;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const STAGING_DIR: &str = "results/staging";
const OBJECTS_DIR: &str = "results/objects";
const QUARANTINE_DIR: &str = "results/quarantine";
/// The reserved local name of the canonical manifest (RP-005).
const MANIFEST_FILENAME: &str = "manifest.json";

/// The Store operations publication storage relies on. `Store` is the
/// production ledger; tests drive the same SQL through a seeded connection.
pub(crate) trait ResultLedger {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError>;
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError>;
    fn abandon(&self, result_id: &str) -> Result<(), CoreError>;
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError>;
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError>;
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError>;
}

/// Shared ledgers (an `Arc<Store>` moved onto a blocking thread).
impl<L: ResultLedger + ?Sized> ResultLedger for Arc<L> {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        (**self).reserve(request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        (**self).mark_prepared(result_id)
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        (**self).abandon(result_id)
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        (**self).claim_reclaim()
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        (**self).confirm_reclaimed(objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        (**self).known_objects(names)
    }
}

impl ResultLedger for crate::Store {
    fn reserve(&self, request: PublicationReservation) -> Result<(), CoreError> {
        self.reserve_publication(request)
    }
    fn mark_prepared(&self, result_id: &str) -> Result<(), CoreError> {
        self.mark_publication_prepared(result_id.to_owned())
    }
    fn abandon(&self, result_id: &str) -> Result<(), CoreError> {
        self.abandon_publication(result_id.to_owned())
    }
    fn claim_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        self.claim_publication_reclaim()
    }
    fn confirm_reclaimed(&self, objects: Vec<String>) -> Result<u64, CoreError> {
        self.confirm_publication_reclaimed(objects)
    }
    fn known_objects(&self, names: Vec<String>) -> Result<Vec<String>, CoreError> {
        self.known_result_objects(names)
    }
}

fn from_store(error: CoreError) -> PublicationError {
    match error {
        CoreError::CapacityExceeded(limit) => PublicationError::Capacity(limit),
        CoreError::Conflict => PublicationError::Stale,
        CoreError::Busy => PublicationError::Busy,
        _ => PublicationError::Storage,
    }
}

fn storage(_: PlatformError) -> PublicationError {
    PublicationError::Storage
}

fn under(directory: &str, name: &str) -> Result<RelativePath, PublicationError> {
    RelativePath::parse(format!("{directory}/{name}")).map_err(storage)
}

/// One durably prepared private file, bound to its recorded identity.
pub(crate) struct PreparedFile {
    object_name: String,
    role: FileRole,
    filename: String,
    media_type: String,
    byte_length: u64,
    sha256: [u8; 32],
    durable: DurableArtifact,
}

impl PreparedFile {
    pub(crate) fn object_name(&self) -> &str {
        &self.object_name
    }
    pub(crate) fn role(&self) -> FileRole {
        self.role
    }
    pub(crate) fn filename(&self) -> &str {
        &self.filename
    }
    pub(crate) fn media_type(&self) -> &str {
        &self.media_type
    }
    pub(crate) fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub(crate) fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub(crate) fn durable(&self) -> &DurableArtifact {
        &self.durable
    }
}

/// Every file of one publication is durable and the Store records the
/// allocation `prepared`. Only `prepare_publication` constructs it; RP-P03's
/// commit consumes it. Nothing is public yet.
pub(crate) struct PreparedPublication {
    result_id: String,
    publication_id: String,
    job_id: JobId,
    attempt_id: String,
    published_at_ms: u64,
    manifest_version: &'static str,
    files: Vec<PreparedFile>,
}

impl PreparedPublication {
    pub(crate) fn result_id(&self) -> &str {
        &self.result_id
    }
    pub(crate) fn publication_id(&self) -> &str {
        &self.publication_id
    }
    pub(crate) fn job_id(&self) -> &JobId {
        &self.job_id
    }
    pub(crate) fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    /// The time recorded inside the manifest bytes.
    pub(crate) fn published_at_ms(&self) -> u64 {
        self.published_at_ms
    }
    pub(crate) fn manifest_version(&self) -> &'static str {
        self.manifest_version
    }
    pub(crate) fn files(&self) -> &[PreparedFile] {
        &self.files
    }

    /// The authoritative commit request for these durable witnesses, bound
    /// to the attempt that produced them and its native cleanup witness.
    /// This is the only production constructor of a `PublicationCommit`.
    pub(crate) fn into_commit(
        self,
        dispatch: &crate::store::execution::DispatchRecord,
        cleanup: crate::store::cleanup::CleanupEvidence,
    ) -> Result<crate::store::results_commit::PublicationCommit, PublicationError> {
        if dispatch.job_id != self.job_id || dispatch.attempt_id != self.attempt_id {
            return Err(PublicationError::Stale);
        }
        Ok(crate::store::results_commit::PublicationCommit {
            attempt: crate::store::cleanup::AttemptRef::from(dispatch),
            cleanup,
            result_id: self.result_id,
            publication_id: self.publication_id,
            manifest_version: self.manifest_version.to_owned(),
            published_at_ms: self.published_at_ms,
            files: self
                .files
                .into_iter()
                .map(|file| crate::store::results_commit::CommittedFile {
                    object_name: file.object_name,
                    role: file.role,
                    byte_length: file.byte_length,
                    sha256: file.sha256,
                })
                .collect(),
        })
    }
}

fn new_id(prefix: &str) -> Result<String, PublicationError> {
    crate::store::random_id(prefix).map_err(|_| PublicationError::Storage)
}

/// Points inside preparation where tests inject native faults (RP-P02/7).
/// Production passes a hook that does nothing.
pub(super) enum PrepareStep<'a> {
    /// Before one file's durable write.
    Write(FileRole),
    /// After one file's durable write, holding the bytes read back from it.
    ReadBack(FileRole, &'a mut Vec<u8>),
}

type PrepareHook<'h> = dyn FnMut(PrepareStep<'_>) -> Result<(), PlatformError> + 'h;

/// Durably prepare one validated candidate and its canonical manifest.
pub(super) fn prepare_publication(
    ledger: &impl ResultLedger,
    root: &OwnedRoot,
    candidate: &ValidatedCandidate,
    deadline: Instant,
) -> Result<PreparedPublication, PublicationError> {
    prepare_publication_with(ledger, root, candidate, deadline, &mut |_| Ok(()))
}

/// Prepare on a blocking thread. The caller may stop waiting (it is aborted,
/// or its deadline passes) without cancelling anything: the blocking task
/// owns the ledger, root and candidate, and its allocation stays `preparing`
/// (never reclaimed while this session is active) until the native work
/// returns and records `prepared` or `failed` itself. Giving up therefore
/// frees no space and makes no content unreferenced (reference: the input
/// upload budget's ownership of non-cancellable native work).
pub(super) async fn prepare_publication_blocking<L>(
    ledger: L,
    root: Arc<OwnedRoot>,
    candidate: ValidatedCandidate,
    deadline: Instant,
) -> Result<PreparedPublication, PublicationError>
where
    L: ResultLedger + Send + 'static,
{
    prepare_blocking_with(ledger, root, candidate, deadline, |_| Ok(())).await
}

async fn prepare_blocking_with<L, H>(
    ledger: L,
    root: Arc<OwnedRoot>,
    candidate: ValidatedCandidate,
    deadline: Instant,
    mut hook: H,
) -> Result<PreparedPublication, PublicationError>
where
    L: ResultLedger + Send + 'static,
    H: FnMut(PrepareStep<'_>) -> Result<(), PlatformError> + Send + 'static,
{
    budget(deadline)?;
    let task = tokio::task::spawn_blocking(move || {
        prepare_publication_with(&ledger, &root, &candidate, deadline, &mut hook)
    });
    let prepared = tokio::time::timeout_at(deadline.into(), task)
        .await
        .map_err(|_| PublicationError::Deadline)?
        .map_err(|_| PublicationError::Storage)??;
    // Tokio may poll a finished task before its timer. A completion seen
    // after expiry is not a usable witness; its files stay prepared and
    // charged until reclamation.
    budget(deadline)?;
    Ok(prepared)
}

fn prepare_publication_with(
    ledger: &impl ResultLedger,
    root: &OwnedRoot,
    candidate: &ValidatedCandidate,
    deadline: Instant,
    hook: &mut PrepareHook<'_>,
) -> Result<PreparedPublication, PublicationError> {
    budget(deadline)?;
    root.check_durable_mutation_support().map_err(storage)?;
    // Identities exist before any file; the worker chooses none of them.
    let result_id = new_id("res_")?;
    let publication_id = new_id("pub_")?;
    let artifact_id = new_id("art_")?;
    let published_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicationError::Storage)?
        .as_millis() as u64;
    let ManifestBytes {
        version,
        bytes: manifest,
        sha256: manifest_sha256,
    } = candidate.manifest(&result_id, &publication_id, &artifact_id, published_at_ms)?;
    let artifact: Arc<[u8]> = candidate.bytes.clone();
    let files = [
        (
            ReservedFile {
                object_name: artifact_id,
                role: FileRole::Artifact,
                filename: candidate.filename.clone(),
                media_type: "application/octet-stream".to_owned(),
                byte_length: artifact.len() as u64,
                sha256: digest(&artifact, deadline)?,
            },
            artifact,
        ),
        (
            ReservedFile {
                object_name: publication_id.clone(),
                role: FileRole::Manifest,
                filename: MANIFEST_FILENAME.to_owned(),
                media_type: "application/json".to_owned(),
                byte_length: manifest.len() as u64,
                sha256: manifest_sha256,
            },
            Arc::from(manifest),
        ),
    ];
    let available_space_bytes = root.available_space_bytes().map_err(storage)?;
    budget(deadline)?;
    ledger
        .reserve(PublicationReservation {
            result_id: result_id.clone(),
            publication_id: publication_id.clone(),
            job_id: candidate.job_id.as_str().to_owned(),
            attempt_id: candidate.attempt_id.clone(),
            files: files.iter().map(|(file, _)| file.clone()).collect(),
            available_space_bytes,
        })
        .map_err(from_store)?;
    // From here the charge stays until a commit keeps it or reclamation has
    // durably deleted every name below. This call is synchronous: when it
    // returns, its native writes have finished, so an error may hand the
    // allocation to reclamation. If recording that fails the allocation stays
    // `preparing` and is reclaimed only after restart.
    let written = (|| {
        let mut prepared = Vec::with_capacity(files.len());
        for (file, bytes) in files {
            budget(deadline)?;
            let durable = prepare_file(root, &file, &bytes, deadline, hook)?;
            prepared.push(PreparedFile {
                object_name: file.object_name,
                role: file.role,
                filename: file.filename,
                media_type: file.media_type,
                byte_length: file.byte_length,
                sha256: file.sha256,
                durable,
            });
        }
        budget(deadline)?;
        ledger.mark_prepared(&result_id).map_err(from_store)?;
        Ok(prepared)
    })();
    let prepared = match written {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = ledger.abandon(&result_id);
            return Err(error);
        }
    };
    Ok(PreparedPublication {
        result_id,
        publication_id,
        job_id: candidate.job_id.clone(),
        attempt_id: candidate.attempt_id.clone(),
        published_at_ms,
        manifest_version: version,
        files: prepared,
    })
}

fn prepare_file(
    root: &OwnedRoot,
    file: &ReservedFile,
    bytes: &[u8],
    deadline: Instant,
    hook: &mut PrepareHook<'_>,
) -> Result<DurableArtifact, PublicationError> {
    hook(PrepareStep::Write(file.role)).map_err(storage)?;
    let object = under(OBJECTS_DIR, &file.object_name)?;
    let durable = root
        .prepare_artifact(&under(STAGING_DIR, &file.object_name)?, &object, bytes)
        .map_err(storage)?;
    // Recompute length and digest from what is durably stored, through a
    // fresh no-follow private handle, before any witness is offered.
    let mut stored = Vec::with_capacity(bytes.len());
    root.open_immutable_input(&object)
        .map_err(storage)?
        .take(file.byte_length.saturating_add(1))
        .read_to_end(&mut stored)
        .map_err(|_| PublicationError::Storage)?;
    hook(PrepareStep::ReadBack(file.role, &mut stored)).map_err(storage)?;
    if durable.length() != file.byte_length
        || stored.len() as u64 != file.byte_length
        || digest(&stored, deadline)? != file.sha256
    {
        return Err(PublicationError::Storage);
    }
    Ok(durable)
}

/// What one reclamation turn achieved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReclaimReport {
    pub(crate) deleted: usize,
    pub(crate) released_bytes: u64,
    /// The Store handed out files this turn, so another turn may find more.
    pub(crate) more: bool,
}

/// Durably delete one bounded batch of reclaimable files, then release the
/// charge of allocations left with none. A failed deletion stops the turn;
/// only names already durably removed are confirmed.
pub(crate) fn reclaim_turn(
    ledger: &impl ResultLedger,
    root: &OwnedRoot,
) -> Result<ReclaimReport, PublicationError> {
    root.check_durable_mutation_support().map_err(storage)?;
    let batch = ledger.claim_reclaim().map_err(from_store)?;
    let mut removed = Vec::with_capacity(batch.objects.len());
    let mut failure = None;
    for name in &batch.objects {
        match remove_everywhere(root, name) {
            Ok(()) => removed.push(name.clone()),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let deleted = removed.len();
    let released = if removed.is_empty() {
        0
    } else {
        ledger.confirm_reclaimed(removed).map_err(from_store)?
    };
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(ReclaimReport {
        deleted,
        released_bytes: batch.released_bytes.saturating_add(released),
        more: !batch.objects.is_empty(),
    })
}

/// Why one committed file cannot be served accurately (RP-004, RP-P03/7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArtifactFault {
    /// The committed file is gone: `artifact_unavailable`.
    Unavailable,
    /// The file is present but is not exactly its committed bytes, or cannot
    /// be read safely: `storage_integrity_fault`.
    Integrity,
}

/// Read one committed file through a fresh confined, no-follow private
/// handle and check it against its committed length and digest. A fault is
/// reported as found: nothing is re-hashed into the record, rebuilt,
/// rewritten or run as another attempt. A reference that is not a generated
/// object name is never opened.
pub(crate) fn read_committed(
    root: &OwnedRoot,
    file: &crate::store::results_commit::CommittedFile,
) -> Result<Vec<u8>, ArtifactFault> {
    use sha2::{Digest, Sha256};
    if !generated_name(&file.object_name, "art_") && !generated_name(&file.object_name, "pub_") {
        return Err(ArtifactFault::Integrity);
    }
    let object = under(OBJECTS_DIR, &file.object_name).map_err(|_| ArtifactFault::Integrity)?;
    let reader = match root.open_immutable_input(&object) {
        Ok(reader) => reader,
        Err(PlatformError::NotFound) => return Err(ArtifactFault::Unavailable),
        Err(_) => return Err(ArtifactFault::Integrity),
    };
    let mut bytes = Vec::new();
    reader
        .take(file.byte_length.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ArtifactFault::Integrity)?;
    if bytes.len() as u64 != file.byte_length || Sha256::digest(&bytes)[..] != file.sha256 {
        return Err(ArtifactFault::Integrity);
    }
    Ok(bytes)
}

/// Verify all committed files of one result for `GET /v1/results` availability
/// reporting (`RP-003`, `RP-004`, `RP-S09`). Integrity faults take precedence
/// over missing files; nothing is mutated or regenerated.
pub(crate) fn check_result_availability(
    root: &OwnedRoot,
    files: &[crate::store::results_commit::CommittedFile],
) -> dissect3d_api::ResultAvailability {
    use dissect3d_api::ResultAvailability;
    if files.is_empty() {
        return ResultAvailability::IntegrityFault;
    }
    let mut missing = false;
    for file in files {
        match read_committed(root, file) {
            Ok(_) => {}
            Err(ArtifactFault::Unavailable) => missing = true,
            Err(ArtifactFault::Integrity) => return ResultAvailability::IntegrityFault,
        }
    }
    if missing {
        ResultAvailability::Unavailable
    } else {
        ResultAvailability::Available
    }
}

fn remove_everywhere(root: &OwnedRoot, name: &str) -> Result<(), PublicationError> {
    if !generated_name(name, "art_") && !generated_name(name, "pub_") {
        return Err(PublicationError::Storage);
    }
    for directory in [OBJECTS_DIR, STAGING_DIR] {
        match root.remove_durable(&under(directory, name)?) {
            Ok(()) | Err(PlatformError::NotFound) => {}
            Err(error) => return Err(storage(error)),
        }
    }
    Ok(())
}

/// Position of a bounded sweep over the result directories.
#[derive(Default)]
pub(crate) struct AuditCursor {
    directory: usize,
    scan: Option<OwnedInputScan>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuditReport {
    pub(crate) checked: usize,
    pub(crate) quarantined: usize,
    /// The sweep has visited every entry; start a new cursor to sweep again.
    pub(crate) exhausted: bool,
}

/// Check up to 64 entries of the private result directories against the
/// Store's references. A referenced name stays; an unreferenced or foreign
/// entry (including links, folders and undecodable names) is moved to
/// `results/quarantine` without being opened or deleted. A failed lookup is
/// unknown, not absence: the turn stops and keeps everything.
pub(crate) fn audit_turn(
    ledger: &impl ResultLedger,
    root: &OwnedRoot,
    cursor: &mut AuditCursor,
) -> Result<AuditReport, PublicationError> {
    root.check_durable_mutation_support().map_err(storage)?;
    let directories = [OBJECTS_DIR, STAGING_DIR];
    while let Some(directory) = directories.get(cursor.directory) {
        let relative = RelativePath::parse(*directory).map_err(storage)?;
        if cursor.scan.is_none() {
            match root.scan_owned_inputs(&relative) {
                Ok(scan) => cursor.scan = Some(scan),
                Err(PlatformError::NotFound) => {
                    cursor.directory += 1;
                    continue;
                }
                Err(error) => return Err(storage(error)),
            }
        }
        let Some(scan) = cursor.scan.as_mut() else {
            return Err(PublicationError::Storage);
        };
        let batch = scan
            .next_batch(crate::domain::publication_policy::RECLAIM_ENTRIES_PER_TURN)
            .map_err(storage)?;
        let names = batch
            .entries
            .iter()
            .filter_map(|entry| entry.as_str().rsplit('/').next())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let generated = names
            .iter()
            .filter(|n| generated_name(n, "art_") || generated_name(n, "pub_"))
            .cloned()
            .collect::<Vec<_>>();
        let known = ledger.known_objects(generated).map_err(from_store)?;
        let mut quarantined = 0;
        for name in names.iter().filter(|name| !known.contains(name)) {
            quarantine(root, &relative, std::ffi::OsStr::new(name))?;
            quarantined += 1;
        }
        for name in &batch.rejected_names {
            quarantine(root, &relative, name)?;
            quarantined += 1;
        }
        if batch.exhausted {
            cursor.scan = None;
            cursor.directory += 1;
        }
        return Ok(AuditReport {
            checked: names.len() + batch.rejected_names.len(),
            quarantined,
            exhausted: cursor.directory >= directories.len(),
        });
    }
    Ok(AuditReport {
        exhausted: true,
        ..AuditReport::default()
    })
}

fn quarantine(
    root: &OwnedRoot,
    directory: &RelativePath,
    name: &std::ffi::OsStr,
) -> Result<(), PublicationError> {
    let destination = under(QUARANTINE_DIR, &new_id("q_")?)?;
    match root.quarantine_owned_entry(directory, name, &destination) {
        // Reclamation may have removed it between listing and here.
        Ok(()) | Err(PlatformError::NotFound) => Ok(()),
        Err(error) => Err(storage(error)),
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
