//! Creator-scoped history and high-water pagination, serialized by the actor.

use super::*;
use crate::submission::SubmissionError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dissect3d_api::{
    ErrorCode, JobId, JobPage, JobSnapshot, JobState, JobSummary, JobsQuery, ResolvedJob,
    StorageStatus,
};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, SubmissionError>;

/// Versioned high-water cursor bound to this installation, engine instance,
/// creator, collection, order and limit (DS-C06: at most 1,024 bytes). A distinct
/// `collection` keeps one collection's cursor from being replayed on another.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    version: String,
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    collection: String,
    order: String,
    limit: u8,
    high_water: i64,
    after_sequence: i64,
}

fn invalid() -> SubmissionError {
    ErrorCode::InvalidRequest.into()
}
fn storage() -> SubmissionError {
    ErrorCode::StoreUnavailable.into()
}

pub(crate) struct AuditEntry {
    pub(crate) id: dissect3d_api::InputId,
    pub(crate) identity: Option<dissect3d_api::InputIdentity>,
}

pub(super) fn audit_batch(connection: &Connection, after: String) -> Result<Vec<AuditEntry>> {
    let mut statement = sql(connection.prepare(
        "SELECT DISTINCT ji.input_id,c.media_type,c.byte_length,c.sha256
        FROM job_inputs ji LEFT JOIN captured_inputs c ON c.input_id=ji.input_id
        WHERE ji.input_id>?1 ORDER BY ji.input_id LIMIT 2",
    ))?;
    let rows = sql(statement.query_map([after], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<i64>>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
        ))
    }))?;
    rows.map(|row| {
        let (id, media, length, digest) = sql(row)?;
        let id = dissect3d_api::InputId::parse(id).map_err(|_| storage())?;
        let identity = match (media, length, digest) {
            (Some(media_type), Some(length), Some(digest)) => Some(dissect3d_api::InputIdentity {
                input_id: id.clone(),
                media_type,
                byte_length: u64::try_from(length).map_err(|_| storage())?,
                sha256: dissect3d_api::ContentDigest::parse(digest_hex(
                    digest.as_slice().try_into().map_err(|_| storage())?,
                ))
                .map_err(|_| storage())?,
            }),
            _ => None,
        };
        Ok(AuditEntry { id, identity })
    })
    .collect()
}

pub(super) fn mark_fault(connection: &Connection, id: dissect3d_api::InputId) -> Result<()> {
    sql(connection.execute(
        "UPDATE jobs SET storage_status='storage_integrity_fault' WHERE job_id IN
        (SELECT job_id FROM job_inputs WHERE input_id=?1)",
        [id.as_str()],
    ))?;
    Ok(())
}

pub(super) fn summary(id: String, sequence: i64, created: i64) -> Result<JobSummary> {
    Ok(JobSummary {
        job_id: JobId::parse(id).map_err(|_| storage())?,
        acceptance_sequence: sequence,
        snapshot_revision: 1,
        state: JobState::Queued,
        blockers: vec!["execution_unavailable".into()],
        created_at_ms: TimestampMs::new(u64::try_from(created).map_err(|_| storage())?)
            .map_err(|_| storage())?,
    })
}

pub(super) fn show(
    connection: &Connection,
    auth: AuthContext,
    id: JobId,
    response_limit: usize,
) -> Result<JobSnapshot> {
    require_active_grant(connection, &auth, "jobs.show")?;
    let row: Option<(i64, i64, String, String, Option<String>)> = sql(connection
        .query_row(
            "SELECT acceptance_sequence,created_at_ms,resolved_json,storage_status,
                (SELECT state FROM job_execution e WHERE e.job_id=jobs.job_id)
         FROM jobs WHERE job_id=?1 AND client_id=?2",
            rusqlite::params![id.as_str(), auth.client_id.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional())?;
    let (sequence, created, resolved, status, state) =
        row.ok_or_else(|| SubmissionError::from(ErrorCode::NotFound))?;
    legacy_queued(state.as_deref())?;
    let resolved: ResolvedJob = dissect3d_api::decode_submission_json(resolved.as_bytes(), 262_144)
        .map_err(|_| storage())?;
    resolved.validate().map_err(|_| storage())?;
    let snapshot = JobSnapshot {
        api_version: "1.0".into(),
        summary: summary(id.as_str().to_owned(), sequence, created)?,
        resolved,
        storage_status: match status.as_str() {
            "verified" => StorageStatus::Verified,
            "storage_integrity_fault" => StorageStatus::StorageIntegrityFault,
            _ => return Err(storage()),
        },
        attempt_id: None,
        result_id: None,
    };
    if serde_json::to_vec(&snapshot).map_err(|_| storage())?.len() > response_limit.min(262_144) {
        return Err(storage());
    }
    Ok(snapshot)
}

pub(super) fn list(
    connection: &Connection,
    auth: AuthContext,
    query: JobsQuery,
    response_limit: usize,
) -> Result<JobPage> {
    require_active_grant(connection, &auth, "jobs.list")?;
    let limit = page_limit(query.limit)?;
    let cursor = Cursor::open(connection, &auth, query.cursor, limit, "jobs")?;
    let mut statement=sql(connection.prepare("SELECT job_id,acceptance_sequence,created_at_ms,
            (SELECT state FROM job_execution e WHERE e.job_id=jobs.job_id) FROM jobs
        WHERE client_id=?1 AND acceptance_sequence>?2 AND acceptance_sequence<=?3 ORDER BY acceptance_sequence LIMIT ?4"))?;
    let rows = sql(statement.query_map(
        rusqlite::params![
            auth.client_id.as_str(),
            cursor.after_sequence,
            cursor.high_water,
            i64::from(limit) + 1
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        },
    ))?;
    let mut items = rows
        .enumerate()
        .map(|(index, row)| {
            let (id, sequence, created, state) = sql(row)?;
            // The look-ahead row only signals `more`; it is never shown.
            if index < usize::from(limit) {
                legacy_queued(state.as_deref())?;
            }
            summary(id, sequence, created)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut more = items.len() > usize::from(limit);
    items.truncate(usize::from(limit));
    loop {
        let next_cursor = if more {
            Some(cursor.after(items.last().ok_or_else(storage)?.acceptance_sequence)?)
        } else {
            None
        };
        let page = JobPage {
            api_version: "1.0".into(),
            items: items.clone(),
            next_cursor,
            truncated: more,
        };
        if serde_json::to_vec(&page).map_err(|_| storage())?.len() <= response_limit.min(262_144) {
            return Ok(page);
        }
        items.pop().ok_or_else(storage)?;
        more = true;
    }
}

/// WE-001: an unnegotiated read never shows active or terminal work as queued
/// and never drops it. Once a job is not queued, its legacy show and any legacy
/// page containing it fail explicitly; queued-only reads keep their old form.
fn legacy_queued(state: Option<&str>) -> Result<()> {
    match state {
        Some("queued") => Ok(()),
        Some(_) => Err(ErrorCode::IncompatibleContract.into()),
        None => Err(storage()),
    }
}

/// DS-C06 page size: default 20, at most 100.
pub(super) fn page_limit(limit: Option<u8>) -> Result<u8> {
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(invalid());
    }
    Ok(limit)
}

impl Cursor {
    /// Validate a supplied cursor for this collection, or start a new one at the
    /// creator's current high water. Other creators' rows never move either bound.
    pub(super) fn open(
        connection: &Connection,
        auth: &AuthContext,
        text: Option<String>,
        limit: u8,
        collection: &'static str,
    ) -> Result<Self> {
        let identity = read_identity(connection)?;
        let Some(text) = text else {
            let high_water: i64 = sql(connection.query_row(
                "SELECT coalesce(max(acceptance_sequence),0) FROM jobs WHERE client_id=?1",
                [auth.client_id.as_str()],
                |row| row.get(0),
            ))?;
            return Ok(Self {
                version: "1.0".into(),
                installation_id: identity.installation_id,
                instance_id: identity.instance_id,
                client_id: auth.client_id.clone(),
                collection: collection.into(),
                order: "acceptance_sequence_asc".into(),
                limit,
                high_water,
                after_sequence: 0,
            });
        };
        if text.len() > 1024 {
            return Err(invalid());
        }
        let bytes = URL_SAFE_NO_PAD.decode(&text).map_err(|_| invalid())?;
        if URL_SAFE_NO_PAD.encode(&bytes) != text {
            return Err(invalid());
        }
        let cursor: Self = dissect3d_api::decode_json(&bytes).map_err(|_| invalid())?;
        if cursor.version != "1.0"
            || cursor.collection != collection
            || cursor.order != "acceptance_sequence_asc"
            || cursor.installation_id != identity.installation_id
            || cursor.client_id != auth.client_id
            || cursor.limit != limit
            || cursor.after_sequence <= 0
            || cursor.high_water <= cursor.after_sequence
        {
            return Err(invalid());
        }
        if cursor.instance_id != identity.instance_id {
            return Err(ErrorCode::JobCursorExpired.into());
        }
        for sequence in [cursor.after_sequence, cursor.high_water] {
            let exists: bool = sql(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM jobs WHERE client_id=?1 AND acceptance_sequence=?2)",
                rusqlite::params![auth.client_id.as_str(), sequence],
                |row| row.get(0),
            ))?;
            if !exists {
                return Err(invalid());
            }
        }
        Ok(cursor)
    }

    /// Exclusive lower and inclusive upper acceptance sequence of this page.
    pub(super) fn bounds(&self) -> (i64, i64) {
        (self.after_sequence, self.high_water)
    }

    /// The encoded cursor for the page after `after_sequence`.
    pub(super) fn after(&self, after_sequence: i64) -> Result<String> {
        let state = Self {
            after_sequence,
            ..self.clone()
        };
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&state).map_err(|_| storage())?))
    }
}
