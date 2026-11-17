//! Private execution snapshots. SQL captures rows; bounded callers decode them.
use super::*;
use crate::submission::SubmissionError;
use dissect3d_api::{
    CleanupStatus, ExecutionCancellation, ExecutionCleanup, ExecutionJobPage, ExecutionJobSnapshot,
    ExecutionJobState, ExecutionJobSummary, ExecutionOutcome, ExecutionPolicy, ExecutionRecord,
    JobId, JobsQuery, StorageStatus,
};

pub(super) enum ReadCommand {
    Snapshot(
        AuthContext,
        JobId,
        SyncSender<Result<RawSnapshot, CoreError>>,
    ),
    Confirm(
        AuthContext,
        JobId,
        i64,
        String,
        SyncSender<Result<bool, CoreError>>,
    ),
    Page(
        AuthContext,
        JobsQuery,
        SyncSender<Result<RawPage, SubmissionError>>,
    ),
    ConfirmPage(
        AuthContext,
        Vec<PageKey>,
        SyncSender<Result<bool, CoreError>>,
    ),
}
/// One captured `jobs` + `job_execution` row. The single read and the page both
/// capture it with [`SUMMARY_COLUMNS`] and decode it with [`decode_summary`], so
/// they cannot disagree about any summary field.
pub(super) struct RawSummary {
    id: String,
    sequence: i64,
    created: i64,
    pub(super) revision: i64,
    state: String,
    phase: String,
    progress: Option<String>,
    timeout: Option<i64>,
    canceled: Option<i64>,
    cleanup: String,
    cleanup_reason: Option<String>,
    outcome: Option<String>,
    retry_of: Option<String>,
    attempt: Option<String>,
    pub(super) storage: String,
}
/// Columns read by [`RawSummary::from_row`], in order, over [`SUMMARY_FROM`].
pub(super) const SUMMARY_COLUMNS: &str =
    "j.job_id,j.acceptance_sequence,j.created_at_ms,e.snapshot_revision,e.state,e.phase,
     e.progress_json,e.timeout_ms,e.cancel_requested_at_ms,e.cleanup_status,e.cleanup_reason,
     e.outcome_code,e.retry_of,a.attempt_id,j.storage_status";
/// One row per job: `job_execution` is 1:1 and one attempt per job is unique.
pub(super) const SUMMARY_FROM: &str = "FROM jobs j
     JOIN job_execution e USING(job_id)
     LEFT JOIN job_attempts a USING(job_id)";
impl RawSummary {
    pub(super) fn from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            sequence: r.get(1)?,
            created: r.get(2)?,
            revision: r.get(3)?,
            state: r.get(4)?,
            phase: r.get(5)?,
            progress: r.get(6)?,
            timeout: r.get(7)?,
            canceled: r.get(8)?,
            cleanup: r.get(9)?,
            cleanup_reason: r.get(10)?,
            outcome: r.get(11)?,
            retry_of: r.get(12)?,
            attempt: r.get(13)?,
            storage: r.get(14)?,
        })
    }
}
pub(super) struct RawSnapshot {
    summary: RawSummary,
    resolved: String,
    response_limit: usize,
}
impl ReadCommand {
    pub(super) fn handle(self, db: &Connection, response_limit: usize) {
        match self {
            Self::Snapshot(auth, id, reply) => {
                let _ = reply.send(read(db, &auth, id, response_limit));
            }
            Self::Confirm(auth, id, revision, storage, reply) => {
                let result = (|| {
                    require_active_grant(db, &auth, "jobs.show")?;
                    sql(db
                        .query_row(
                            "SELECT e.snapshot_revision=?3 AND j.storage_status=?4
                             FROM jobs j JOIN job_execution e USING(job_id)
                             WHERE j.job_id=?1 AND j.client_id=?2",
                            rusqlite::params![
                                id.as_str(),
                                auth.client_id.as_str(),
                                revision,
                                storage
                            ],
                            |r| r.get::<_, bool>(0),
                        )
                        .optional())?
                    .ok_or(CoreError::NotFound)
                })();
                let _ = reply.send(result);
            }
            Self::Page(auth, query, reply) => {
                let _ = reply.send(read_page(db, &auth, query, response_limit));
            }
            Self::ConfirmPage(auth, keys, reply) => {
                let _ = reply.send(confirm_page(db, &auth, &keys));
            }
        }
    }
}
fn read(
    db: &Connection,
    auth: &AuthContext,
    id: JobId,
    response_limit: usize,
) -> Result<RawSnapshot, CoreError> {
    require_active_grant(db, auth, "jobs.show")?;
    sql(db
        .query_row(
            &format!(
                "SELECT {SUMMARY_COLUMNS},j.resolved_json {SUMMARY_FROM}
                 WHERE j.job_id=?1 AND j.client_id=?2"
            ),
            rusqlite::params![id.as_str(), auth.client_id.as_str()],
            |r| {
                Ok(RawSnapshot {
                    summary: RawSummary::from_row(r)?,
                    resolved: r.get(15)?,
                    response_limit,
                })
            },
        )
        .optional())?
    .ok_or(CoreError::NotFound)
}
fn timestamp(value: i64) -> Result<TimestampMs, CoreError> {
    TimestampMs::new(value.try_into().map_err(|_| CoreError::InvalidStore)?)
        .map_err(|_| CoreError::InvalidStore)
}
/// Decode and validate one stored row; a corrupt row fails closed, never skipped.
pub(super) fn decode_summary(row: &RawSummary) -> Result<ExecutionJobSummary, CoreError> {
    let state = match row.state.as_str() {
        "queued" => ExecutionJobState::Queued,
        "running" => ExecutionJobState::Running,
        "cancel_requested" => ExecutionJobState::CancelRequested,
        "failed" => ExecutionJobState::Failed,
        "canceled" => ExecutionJobState::Canceled,
        "interrupted" => ExecutionJobState::Interrupted,
        // RP-P03 must supply real committed result identities before reads of
        // successful outcomes can be implemented. Do not fabricate empty results.
        "succeeded" | "partial" => return Err(CoreError::Busy),
        _ => return Err(CoreError::InvalidStore),
    };
    let cleanup = match row.cleanup.as_str() {
        "pending" => CleanupStatus::Pending,
        "confirmed" => CleanupStatus::Confirmed,
        "fault" => CleanupStatus::Fault,
        _ => return Err(CoreError::InvalidStore),
    };
    let storage = match row.storage.as_str() {
        "verified" => StorageStatus::Verified,
        "storage_integrity_fault" => StorageStatus::StorageIntegrityFault,
        _ => return Err(CoreError::InvalidStore),
    };
    let progress = row
        .progress
        .as_ref()
        .map(|s| {
            dissect3d_api::decode_submission_json(
                s.as_bytes(),
                super::execution::PROGRESS_JSON_BYTES_MAX,
            )
            .map_err(|_| CoreError::InvalidStore)
        })
        .transpose()?;
    let summary = ExecutionJobSummary {
        api_version: "1.0".into(),
        job_contract: dissect3d_api::JOB_CONTRACT.into(),
        job_id: JobId::parse(&row.id).map_err(|_| CoreError::InvalidStore)?,
        acceptance_sequence: row.sequence,
        created_at_ms: timestamp(row.created)?,
        snapshot_revision: row
            .revision
            .try_into()
            .map_err(|_| CoreError::InvalidStore)?,
        state,
        phase: row.phase.clone(),
        progress,
        blockers: if state == ExecutionJobState::Queued {
            vec!["execution_unavailable".into()]
        } else {
            vec![]
        },
        attempt_id: row.attempt.clone(),
        cancellation: ExecutionCancellation {
            requested: row.canceled.is_some(),
            requested_at_ms: row.canceled.map(timestamp).transpose()?,
        },
        execution_policy: ExecutionPolicy {
            timeout_ms: row
                .timeout
                .map(|v| v.try_into().map_err(|_| CoreError::InvalidStore))
                .transpose()?,
        },
        cleanup: ExecutionCleanup {
            status: cleanup,
            reason: row.cleanup_reason.clone(),
        },
        result_ids: vec![],
        retry_of: row
            .retry_of
            .as_ref()
            .map(|v| JobId::parse(v).map_err(|_| CoreError::InvalidStore))
            .transpose()?,
        outcome: row.outcome.as_ref().map(|code| ExecutionOutcome {
            code: code.clone(),
            retryable: matches!(
                state,
                ExecutionJobState::Failed
                    | ExecutionJobState::Canceled
                    | ExecutionJobState::Interrupted
            ),
        }),
        storage_status: storage,
    };
    summary.validate().map_err(|_| CoreError::InvalidStore)?;
    Ok(summary)
}
fn decode(row: &RawSnapshot) -> Result<ExecutionJobSnapshot, CoreError> {
    let snapshot = ExecutionJobSnapshot {
        summary: decode_summary(&row.summary)?,
        resolved: dissect3d_api::decode_submission_json(row.resolved.as_bytes(), 262_144)
            .map_err(|_| CoreError::InvalidStore)?,
    };
    snapshot.validate().map_err(|_| CoreError::InvalidStore)?;
    if serde_json::to_vec(&snapshot)
        .map_err(|_| CoreError::InvalidStore)?
        .len()
        > row.response_limit.min(262_144)
    {
        return Err(CoreError::CapacityExceeded("control_response_bytes"));
    }
    Ok(snapshot)
}
/// The facts a page item was decoded from, rechecked before the page returns.
pub(super) struct PageKey {
    id: String,
    revision: i64,
    storage: String,
}
/// One captured creator-scoped page: grant, cursor bounds and rows come from one
/// read transaction; decoding and packing happen in the caller.
pub(super) struct RawPage {
    cursor: jobs::Cursor,
    rows: Vec<RawSummary>,
    more: bool,
    pub(super) response_limit: usize,
}
impl RawPage {
    pub(super) fn keys(&self) -> Vec<PageKey> {
        self.rows
            .iter()
            .map(|row| PageKey {
                id: row.id.clone(),
                revision: row.revision,
                storage: row.storage.clone(),
            })
            .collect()
    }
}
/// Distinct from the queued list's `jobs`, so neither cursor replays on the other.
const PAGE_COLLECTION: &str = "execution_jobs";

fn read_page(
    db: &Connection,
    auth: &AuthContext,
    query: JobsQuery,
    response_limit: usize,
) -> Result<RawPage, SubmissionError> {
    let transaction = sql(db.unchecked_transaction())?;
    require_active_grant(&transaction, auth, "jobs.list")?;
    let limit = jobs::page_limit(query.limit)?;
    let cursor = jobs::Cursor::open(&transaction, auth, query.cursor, limit, PAGE_COLLECTION)?;
    let (after, high_water) = cursor.bounds();
    // Creator scope is part of the SQL; other creators' rows are never read.
    let mut rows = {
        let mut statement = sql(transaction.prepare(&format!(
            "SELECT {SUMMARY_COLUMNS} {SUMMARY_FROM}
             WHERE j.client_id=?1 AND j.acceptance_sequence>?2 AND j.acceptance_sequence<=?3
             ORDER BY j.acceptance_sequence LIMIT ?4"
        )))?;
        let rows = sql(statement.query_map(
            rusqlite::params![
                auth.client_id.as_str(),
                after,
                high_water,
                i64::from(limit) + 1
            ],
            RawSummary::from_row,
        ))?;
        rows.map(sql).collect::<Result<Vec<_>, CoreError>>()?
    };
    let more = rows.len() > usize::from(limit);
    rows.truncate(usize::from(limit));
    Ok(RawPage {
        cursor,
        rows,
        more,
        response_limit,
    })
}

fn confirm_page(db: &Connection, auth: &AuthContext, keys: &[PageKey]) -> Result<bool, CoreError> {
    let transaction = sql(db.unchecked_transaction())?;
    require_active_grant(&transaction, auth, "jobs.list")?;
    let mut statement = sql(transaction.prepare(
        "SELECT e.snapshot_revision=?3 AND j.storage_status=?4
         FROM jobs j JOIN job_execution e USING(job_id)
         WHERE j.job_id=?1 AND j.client_id=?2",
    ))?;
    for key in keys {
        let current = sql(statement
            .query_row(
                rusqlite::params![key.id, auth.client_id.as_str(), key.revision, key.storage],
                |r| r.get::<_, bool>(0),
            )
            .optional())?;
        if current != Some(true) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Decode a captured page and pack it under the control response limit. Items
/// stop before the limit with an honest cursor; an item that cannot fit alone is
/// an explicit capacity error, never a silent drop.
pub(super) fn pack(raw: &RawPage) -> Result<ExecutionJobPage, SubmissionError> {
    let capacity = || SubmissionError::from(CoreError::CapacityExceeded("control_response_bytes"));
    let mut items = raw
        .rows
        .iter()
        .map(decode_summary)
        .collect::<Result<Vec<_>, CoreError>>()?;
    let mut more = raw.more;
    let limit = raw.response_limit.min(262_144);
    loop {
        let next_cursor = match (more, items.last()) {
            (false, _) => None,
            (true, Some(last)) => Some(raw.cursor.after(last.acceptance_sequence)?),
            (true, None) => return Err(capacity()),
        };
        let page = ExecutionJobPage {
            api_version: "1.0".into(),
            job_contract: dissect3d_api::JOB_CONTRACT.into(),
            items: items.clone(),
            next_cursor,
            truncated: more,
        };
        if serde_json::to_vec(&page)
            .map_err(|_| admission::invalid_store())?
            .len()
            <= limit
        {
            page.validate().map_err(|_| admission::invalid_store())?;
            return Ok(page);
        }
        if items.pop().is_none() {
            return Err(capacity());
        }
        more = true;
    }
}
impl Store {
    /// Read-only private seam; WE-P06 still owns negotiated route activation.
    /// Same model as the page: bounded by the actor queue, decoded here and
    /// confirmed afterwards. It never takes a submission/retry preparation slot.
    pub(crate) fn execution_job_snapshot(
        &self,
        auth: AuthContext,
        id: JobId,
    ) -> Result<ExecutionJobSnapshot, CoreError> {
        for _ in 0..4 {
            let row = self.request(|reply| {
                Command::ExecutionRead(ReadCommand::Snapshot(auth.clone(), id.clone(), reply))
            })?;
            let snapshot = decode(&row);
            if self.request(|reply| {
                Command::ExecutionRead(ReadCommand::Confirm(
                    auth.clone(),
                    id.clone(),
                    row.summary.revision,
                    row.summary.storage,
                    reply,
                ))
            })? {
                return snapshot;
            }
        }
        Err(CoreError::Busy)
    }

    /// Creator-scoped execution page (private seam; WE-P06 owns the route). It
    /// uses only the bounded actor queue, not the shared preparation gate: rows
    /// are captured in one actor turn, decoded and packed here, and returned only
    /// if every captured revision and the `jobs.list` grant are still current.
    pub(crate) fn execution_job_page(
        &self,
        auth: AuthContext,
        query: JobsQuery,
    ) -> Result<ExecutionJobPage, SubmissionError> {
        for _ in 0..4 {
            let raw = self.request(|reply| {
                Command::ExecutionRead(ReadCommand::Page(auth.clone(), query.clone(), reply))
            })?;
            let page = pack(&raw);
            let fresh: bool = self.request(|reply| {
                Command::ExecutionRead(ReadCommand::ConfirmPage(auth.clone(), raw.keys(), reply))
            })?;
            if fresh {
                return page;
            }
        }
        Err(CoreError::Busy.into())
    }
}
