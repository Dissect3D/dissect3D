//! Store-owned result metadata and accounting (RP-P02/1, /5, /6).
//!
//! Private seams only: no public read, no commit and no dispatch use them yet
//! (RP-P03/RP-P04/WE-P06). Every charge is taken in the same transaction that
//! records the identities and exact file rows, before any byte is written, and
//! is released only when the caller reports durable deletion of every file.
//! A reference lookup that fails is reported as an error, never as absence.
use super::*;
use crate::domain::publication_policy::{
    ARTIFACT_BYTES_PER_ATTEMPT_MAX, MANIFEST_BYTES_PER_ATTEMPT_MAX, PRIVATE_BYTES_MAX,
    PUBLISHED_BYTES_MAX, RECLAIM_BYTES_PER_TURN, RECLAIM_ENTRIES_PER_TURN, RESULT_RECORDS_MAX,
    STORAGE_FREE_RESERVE_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileRole {
    Manifest,
    Artifact,
}
impl FileRole {
    fn as_str(self) -> &'static str {
        match self {
            FileRole::Manifest => "manifest",
            FileRole::Artifact => "artifact",
        }
    }
}

/// One file to be prepared, recorded with its exact length and digest before
/// its bytes are written. `object_name` is the engine-generated private name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReservedFile {
    pub(crate) object_name: String,
    pub(crate) role: FileRole,
    pub(crate) filename: String,
    pub(crate) media_type: String,
    pub(crate) byte_length: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct PublicationReservation {
    pub(crate) result_id: String,
    pub(crate) publication_id: String,
    pub(crate) job_id: String,
    pub(crate) attempt_id: String,
    pub(crate) files: Vec<ReservedFile>,
    /// Observed by the caller just before the request, as for input uploads.
    pub(crate) available_space_bytes: u64,
}

/// Generated private names whose files the caller must durably delete, and
/// charge already released for allocations that had no files left.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ReclaimBatch {
    pub(crate) objects: Vec<String>,
    pub(crate) released_bytes: u64,
}

/// Truthful, store-wide publication usage (RP-005 storage reads build on it).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResultUsage {
    /// Charged until published or durably reclaimed (includes orphans).
    pub(crate) private_bytes: u64,
    /// Exact bytes of committed results' files.
    pub(crate) published_bytes: u64,
    /// Charged allocations whose files may still be partly unwritten.
    pub(crate) unwritten_bytes: u64,
    /// Allocations of every state, the record cap's measure.
    pub(crate) records: u64,
}

pub(super) enum ResultCommand {
    Reserve(PublicationReservation, SyncSender<Result<(), CoreError>>),
    MarkPrepared(String, SyncSender<Result<(), CoreError>>),
    ClaimReclaim(SyncSender<Result<ReclaimBatch, CoreError>>),
    Abandon(String, SyncSender<Result<(), CoreError>>),
    ConfirmReclaimed(Vec<String>, SyncSender<Result<u64, CoreError>>),
    KnownObjects(Vec<String>, SyncSender<Result<Vec<String>, CoreError>>),
    Usage(SyncSender<Result<ResultUsage, CoreError>>),
}

pub(super) fn handle(connection: &mut Connection, command: ResultCommand, stopping: bool) {
    match command {
        ResultCommand::Reserve(request, reply) => {
            // Shutdown stops new charges; reclamation and reads may continue.
            let result = if stopping {
                Err(CoreError::Busy)
            } else {
                reserve(connection, &request)
            };
            let _ = reply.send(result);
        }
        ResultCommand::MarkPrepared(result_id, reply) => {
            let _ = reply.send(mark_prepared(connection, &result_id));
        }
        ResultCommand::Abandon(result_id, reply) => {
            let _ = reply.send(abandon(connection, &result_id));
        }
        ResultCommand::ClaimReclaim(reply) => {
            let _ = reply.send(claim_reclaim(connection));
        }
        ResultCommand::ConfirmReclaimed(objects, reply) => {
            let _ = reply.send(confirm_reclaimed(connection, &objects));
        }
        ResultCommand::KnownObjects(names, reply) => {
            let _ = reply.send(known_objects(connection, &names));
        }
        ResultCommand::Usage(reply) => {
            let _ = reply.send(usage(connection));
        }
    }
}

impl Store {
    pub(crate) fn reserve_publication(
        &self,
        request: PublicationReservation,
    ) -> Result<(), CoreError> {
        self.request(|reply| Command::Results(ResultCommand::Reserve(request, reply)))
    }
    pub(crate) fn mark_publication_prepared(&self, result_id: String) -> Result<(), CoreError> {
        self.request(|reply| Command::Results(ResultCommand::MarkPrepared(result_id, reply)))
    }
    pub(crate) fn abandon_publication(&self, result_id: String) -> Result<(), CoreError> {
        self.request(|reply| Command::Results(ResultCommand::Abandon(result_id, reply)))
    }
    pub(crate) fn claim_publication_reclaim(&self) -> Result<ReclaimBatch, CoreError> {
        self.request(|reply| Command::Results(ResultCommand::ClaimReclaim(reply)))
    }
    pub(crate) fn confirm_publication_reclaimed(
        &self,
        objects: Vec<String>,
    ) -> Result<u64, CoreError> {
        self.request(|reply| Command::Results(ResultCommand::ConfirmReclaimed(objects, reply)))
    }
    pub(crate) fn known_result_objects(
        &self,
        names: Vec<String>,
    ) -> Result<Vec<String>, CoreError> {
        self.request(|reply| Command::Results(ResultCommand::KnownObjects(names, reply)))
    }
    pub(crate) fn result_usage(&self) -> Result<ResultUsage, CoreError> {
        self.request(|reply| Command::Results(ResultCommand::Usage(reply)))
    }
}

/// `prefix` followed by 32 lowercase hex digits: the only names this feature
/// generates for identities and private files.
pub(crate) fn generated_name(value: &str, prefix: &str) -> bool {
    value.len() == 36
        && value.starts_with(prefix)
        && value[4..]
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate(request: &PublicationReservation) -> Result<u64, CoreError> {
    let manifests = request
        .files
        .iter()
        .filter(|f| f.role == FileRole::Manifest)
        .collect::<Vec<_>>();
    let artifacts = request
        .files
        .iter()
        .filter(|f| f.role == FileRole::Artifact)
        .collect::<Vec<_>>();
    let artifact_bytes = artifacts
        .iter()
        .try_fold(0_u64, |sum, f| sum.checked_add(f.byte_length));
    if !generated_name(&request.result_id, "res_")
        || !generated_name(&request.publication_id, "pub_")
        || !generated_name(&request.job_id, "job_")
        || !generated_name(&request.attempt_id, "att_")
        || manifests.len() != 1
        || manifests[0].object_name != request.publication_id
        || !(1..=MANIFEST_BYTES_PER_ATTEMPT_MAX).contains(&manifests[0].byte_length)
        || artifacts.is_empty()
        || artifacts.len() > crate::domain::publication_policy::ARTIFACT_FILES_PER_ATTEMPT_MAX
        || artifacts
            .iter()
            .any(|f| !generated_name(&f.object_name, "art_") || f.byte_length == 0)
        || artifact_bytes.is_none_or(|bytes| bytes > ARTIFACT_BYTES_PER_ATTEMPT_MAX)
        || request.files.iter().any(|f| {
            f.filename.is_empty()
                || f.filename.len() > 255
                || f.media_type.is_empty()
                || f.media_type.len() > 128
        })
    {
        return Err(CoreError::Conflict);
    }
    // Exact charge: every byte this allocation may write.
    artifact_bytes
        .and_then(|bytes| bytes.checked_add(manifests[0].byte_length))
        .ok_or(CoreError::Conflict)
}

fn sum(tx: &Transaction<'_>, query: &str) -> Result<u64, CoreError> {
    let value: i64 = tx
        .query_row(query, [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    u64::try_from(value).map_err(|_| CoreError::InvalidStore)
}

fn usage_in(tx: &Transaction<'_>) -> Result<ResultUsage, CoreError> {
    Ok(ResultUsage {
        private_bytes: sum(
            tx,
            "SELECT coalesce(sum(reserved_bytes),0) FROM publication_allocations
             WHERE state<>'published'",
        )?,
        published_bytes: sum(
            tx,
            "SELECT coalesce(sum(f.byte_length),0) FROM result_files f
             JOIN publication_allocations a USING(result_id) WHERE a.state='published'",
        )?,
        unwritten_bytes: sum(
            tx,
            "SELECT coalesce(sum(reserved_bytes),0) FROM publication_allocations
             WHERE state='preparing'",
        )?,
        records: sum(tx, "SELECT count(*) FROM publication_allocations")?,
    })
}

/// Record identities, exact file rows and the charge for one running attempt.
pub(crate) fn reserve(
    connection: &mut Connection,
    request: &PublicationReservation,
) -> Result<(), CoreError> {
    let charge = validate(request)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Only the attempt that currently runs this job may allocate: a canceled,
    // finished or interrupted attempt can never publish (RP-003).
    let running: i64 = tx
        .query_row(
            "SELECT count(*) FROM job_attempts a JOIN job_execution e USING(job_id)
             WHERE a.attempt_id=?1 AND a.job_id=?2 AND e.state='running'",
            [&request.attempt_id, &request.job_id],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let allocated: i64 = tx
        .query_row(
            "SELECT count(*) FROM publication_allocations WHERE attempt_id=?1",
            [&request.attempt_id],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if running != 1 || allocated != 0 {
        return Err(CoreError::Conflict);
    }
    let current = usage_in(&tx)?;
    let uploads = sum(
        &tx,
        "SELECT coalesce(sum(declared_length),0) FROM input_upload_reservations",
    )?;
    let add = |a: u64, b: u64| a.checked_add(b).ok_or(CoreError::InvalidStore);
    if add(current.private_bytes, charge)? > PRIVATE_BYTES_MAX {
        return Err(CoreError::CapacityExceeded("result_private_bytes_max"));
    }
    // Every charged private byte may become published; count it now.
    if add(add(current.published_bytes, current.private_bytes)?, charge)? > PUBLISHED_BYTES_MAX {
        return Err(CoreError::CapacityExceeded("result_published_bytes_max"));
    }
    if add(current.records, 1)? > RESULT_RECORDS_MAX {
        return Err(CoreError::CapacityExceeded("result_records_max"));
    }
    // A free-space probe cannot promise bytes that other charged writers (input
    // uploads, unfinished preparations) have not written yet.
    let required = add(
        add(add(current.unwritten_bytes, uploads)?, charge)?,
        STORAGE_FREE_RESERVE_BYTES,
    )?;
    if request.available_space_bytes < required {
        return Err(CoreError::CapacityExceeded("storage_free_reserve_bytes"));
    }
    let now = now_ms()?;
    tx.execute(
        "INSERT INTO publication_allocations
         (result_id,publication_id,job_id,attempt_id,instance_id,state,reserved_bytes,created_at_ms,updated_at_ms)
         VALUES(?1,?2,?3,?4,(SELECT instance_id FROM service_sessions WHERE termination='active'),
                'preparing',?5,?6,?6)",
        rusqlite::params![
            request.result_id,
            request.publication_id,
            request.job_id,
            request.attempt_id,
            i64::try_from(charge).map_err(|_| CoreError::Conflict)?,
            now
        ],
    )
    .map_err(|_| CoreError::Conflict)?;
    for file in &request.files {
        tx.execute(
            "INSERT INTO result_files
             (object_name,result_id,role,filename,media_type,byte_length,sha256)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                file.object_name,
                request.result_id,
                file.role.as_str(),
                file.filename,
                file.media_type,
                i64::try_from(file.byte_length).map_err(|_| CoreError::Conflict)?,
                file.sha256.as_slice()
            ],
        )
        // Duplicate or case-aliased names, reused identities, failed checks.
        .map_err(|_| CoreError::Conflict)?;
    }
    tx.commit().map_err(|_| CoreError::StoreUnavailable)
}

/// Every file passed its durable barriers. The charge is unchanged.
pub(crate) fn mark_prepared(connection: &mut Connection, result_id: &str) -> Result<(), CoreError> {
    let now = now_ms()?;
    let changed = connection
        .execute(
            "UPDATE publication_allocations SET state='prepared', updated_at_ms=max(updated_at_ms,?2)
             WHERE result_id=?1 AND state='preparing'",
            rusqlite::params![result_id, now],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(CoreError::Conflict)
    }
}

/// The preparer's native work for this allocation has returned without a
/// witness. The charge stays; reclamation may now take it once the job ends.
pub(crate) fn abandon(connection: &mut Connection, result_id: &str) -> Result<(), CoreError> {
    let now = now_ms()?;
    let changed = connection
        .execute(
            "UPDATE publication_allocations SET state='failed', updated_at_ms=max(updated_at_ms,?2)
             WHERE result_id=?1 AND state='preparing'",
            rusqlite::params![result_id, now],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(CoreError::Conflict)
    }
}

/// Delete reclaiming allocations with no file left; returns released bytes.
fn release_empty(tx: &Transaction<'_>) -> Result<u64, CoreError> {
    let released = sum(
        tx,
        "SELECT coalesce(sum(reserved_bytes),0) FROM publication_allocations a
         WHERE state='reclaiming'
           AND NOT EXISTS (SELECT 1 FROM result_files f WHERE f.result_id=a.result_id)",
    )?;
    tx.execute(
        "DELETE FROM publication_allocations
         WHERE state='reclaiming'
           AND NOT EXISTS (SELECT 1 FROM result_files f WHERE f.result_id=publication_allocations.result_id)",
        [],
    )
    .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(released)
}

/// One bounded reclamation turn. An allocation becomes reclaimable only when
/// the Store already records its job as terminal without a result for it, so
/// a slow or lost caller of a still-running attempt never loses content, and
/// only once no preparer can still write it: `prepared`, `failed`, or
/// `preparing` from an earlier service session. A `preparing` allocation of
/// this session (its preparer may be inside a native write) is never taken.
/// The move to `reclaiming` is permanent: that identity can no longer publish.
pub(crate) fn claim_reclaim(connection: &mut Connection) -> Result<ReclaimBatch, CoreError> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // The fence names "this session" by the active row. After the shutdown
    // barrier marks it clean there is none, and every `preparing` allocation
    // would look like an earlier session's: refuse rather than guess.
    if sum(
        &tx,
        "SELECT count(*) FROM service_sessions WHERE termination='active'",
    )? != 1
    {
        return Err(CoreError::Busy);
    }
    let now = now_ms()?;
    tx.execute(
        "UPDATE publication_allocations SET state='reclaiming', updated_at_ms=max(updated_at_ms,?1)
         WHERE result_id IN (
            SELECT a.result_id FROM publication_allocations a
            JOIN job_execution e USING(job_id)
            WHERE (a.state IN ('prepared','failed')
                   OR (a.state='preparing' AND a.instance_id NOT IN
                       (SELECT instance_id FROM service_sessions WHERE termination='active')))
              AND e.state IN ('succeeded','partial','failed','canceled','interrupted')
              AND NOT EXISTS (SELECT 1 FROM results r WHERE r.result_id=a.result_id)
            ORDER BY a.created_at_ms, a.result_id LIMIT ?2)",
        rusqlite::params![now, RECLAIM_ENTRIES_PER_TURN as i64],
    )
    .map_err(|_| CoreError::StoreUnavailable)?;
    let released_bytes = release_empty(&tx)?;
    let mut objects = Vec::new();
    {
        let mut statement = tx
            .prepare(
                "SELECT f.object_name, f.byte_length FROM result_files f
                 JOIN publication_allocations a USING(result_id)
                 WHERE a.state='reclaiming' ORDER BY f.result_id, f.object_name LIMIT ?1",
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        let rows = statement
            .query_map([RECLAIM_ENTRIES_PER_TURN as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|_| CoreError::StoreUnavailable)?;
        let mut bytes = 0_u64;
        for row in rows {
            let (name, length) = row.map_err(|_| CoreError::StoreUnavailable)?;
            // Bound each turn by entries and by bytes, but always progress.
            if !objects.is_empty() && bytes >= RECLAIM_BYTES_PER_TURN {
                break;
            }
            bytes =
                bytes.saturating_add(u64::try_from(length).map_err(|_| CoreError::InvalidStore)?);
            objects.push(name);
        }
    }
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    Ok(ReclaimBatch {
        objects,
        released_bytes,
    })
}

/// The caller durably deleted these reclaiming files (or proved them absent).
/// Their rows go, and a now-empty allocation releases its charge.
pub(crate) fn confirm_reclaimed(
    connection: &mut Connection,
    objects: &[String],
) -> Result<u64, CoreError> {
    if objects.len() > RECLAIM_ENTRIES_PER_TURN {
        return Err(CoreError::Conflict);
    }
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    for name in objects {
        // Only reclaiming rows: a confirmation can never remove a live file row.
        tx.execute(
            "DELETE FROM result_files WHERE object_name=?1 AND result_id IN
             (SELECT result_id FROM publication_allocations WHERE state='reclaiming')",
            [name],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    }
    let released = release_empty(&tx)?;
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    Ok(released)
}

/// The subset of `names` that some allocation references.
pub(crate) fn known_objects(
    connection: &mut Connection,
    names: &[String],
) -> Result<Vec<String>, CoreError> {
    if names.len() > RECLAIM_ENTRIES_PER_TURN {
        return Err(CoreError::Conflict);
    }
    let mut known = Vec::new();
    let mut statement = connection
        .prepare("SELECT count(*) FROM result_files WHERE object_name=?1")
        .map_err(|_| CoreError::StoreUnavailable)?;
    for name in names {
        let count: i64 = statement
            .query_row([name], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        if count != 0 {
            known.push(name.clone());
        }
    }
    Ok(known)
}

pub(crate) fn usage(connection: &mut Connection) -> Result<ResultUsage, CoreError> {
    let tx = connection
        .transaction()
        .map_err(|_| CoreError::StoreUnavailable)?;
    let usage = usage_in(&tx)?;
    tx.commit().map_err(|_| CoreError::StoreUnavailable)?;
    Ok(usage)
}

#[cfg(test)]
#[path = "results_tests.rs"]
pub(crate) mod tests;
