//! Creator-scoped public read queries for committed results, manifests,
//! artifacts, and storage usage (`RP-004`, `RP-005`).
//!
//! Every read re-verifies the caller's active grant inside SQLite and scopes
//! rows strictly to `jobs.client_id`. Uncommitted allocations (without a
//! `results` row) are never visible through these queries.

use super::results::{FileRole, generated_name};
use super::results_commit::CommittedFile;
use super::*;
use crate::domain::SubmissionError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dissect3d_api::{
    ErrorCode, JobId, ResultAvailability, ResultPage, ResultSummary, ResultsQuery,
    decode_result_page,
};
use serde::{Deserialize, Serialize};

const RESULTS_COLLECTION: &str = "results";

/// Opaque cursor for `GET /v1/results?limit=20&cursor=...` (`RP-004`, `RP-S12`).
///
/// Binds creator, installation, instance, collection, order, limit, the
/// publication high-water sequence captured at traversal start, and the
/// ascending source `acceptance_sequence` seek key.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResultCursor {
    version: String,
    installation_id: InstallationId,
    instance_id: InstanceId,
    client_id: ClientId,
    collection: String,
    order: String,
    limit: u8,
    publication_high_water: i64,
    after_acceptance_sequence: i64,
}

impl ResultCursor {
    fn open(
        connection: &Connection,
        auth: &AuthContext,
        text: Option<String>,
        limit: u8,
    ) -> Result<Self, SubmissionError> {
        let identity = read_identity(connection)?;
        let current_high_water: i64 = sql(connection.query_row(
            "SELECT value FROM publication_sequence WHERE singleton=1",
            [],
            |row| row.get(0),
        ))?;
        let Some(text) = text else {
            return Ok(Self {
                version: "1.0".into(),
                installation_id: identity.installation_id,
                instance_id: identity.instance_id,
                client_id: auth.client_id.clone(),
                collection: RESULTS_COLLECTION.into(),
                order: "acceptance_sequence_asc".into(),
                limit,
                publication_high_water: current_high_water,
                after_acceptance_sequence: 0,
            });
        };
        if text.len() > 1024 {
            return Err(ErrorCode::InvalidRequest.into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&text)
            .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
        if URL_SAFE_NO_PAD.encode(&bytes) != text {
            return Err(ErrorCode::InvalidRequest.into());
        }
        let cursor: Self = dissect3d_api::decode_json(&bytes)
            .map_err(|_| SubmissionError::from(ErrorCode::InvalidRequest))?;
        if cursor.version != "1.0"
            || cursor.collection != RESULTS_COLLECTION
            || cursor.order != "acceptance_sequence_asc"
            || cursor.installation_id != identity.installation_id
            || cursor.client_id != auth.client_id
            || cursor.limit != limit
            || cursor.after_acceptance_sequence <= 0
            || cursor.publication_high_water <= 0
        {
            return Err(ErrorCode::InvalidRequest.into());
        }
        if cursor.instance_id != identity.instance_id {
            return Err(ErrorCode::JobCursorExpired.into());
        }
        if cursor.publication_high_water > current_high_water {
            return Err(ErrorCode::InvalidRequest.into());
        }
        let exists: bool = sql(connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM results r JOIN jobs j USING(job_id)
                WHERE j.client_id=?1
                  AND j.acceptance_sequence=?2
                  AND r.publication_sequence<=?3
             )",
            rusqlite::params![
                auth.client_id.as_str(),
                cursor.after_acceptance_sequence,
                cursor.publication_high_water,
            ],
            |row| row.get(0),
        ))?;
        if !exists {
            return Err(ErrorCode::InvalidRequest.into());
        }
        Ok(cursor)
    }

    fn after(&self, after_acceptance_sequence: i64) -> Result<String, SubmissionError> {
        let next = Self {
            after_acceptance_sequence,
            ..self.clone()
        };
        let encoded = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&next)
                .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?,
        );
        if encoded.len() > 1024 {
            return Err(ErrorCode::StoreUnavailable.into());
        }
        Ok(encoded)
    }
}

/// One committed result row plus its file witnesses, captured in one Store read.
#[derive(Clone, Debug)]
pub(crate) struct RawResultRow {
    pub(crate) result_id: String,
    pub(crate) job_id: JobId,
    pub(crate) attempt_id: String,
    pub(crate) published_at_ms: u64,
    pub(crate) acceptance_sequence: i64,
    pub(crate) files: Vec<CommittedFile>,
}

/// Captured creator-scoped result page before off-actor file availability checks.
pub(crate) struct RawResultPage {
    cursor: ResultCursor,
    pub(crate) rows: Vec<RawResultRow>,
    more: bool,
    response_limit: usize,
}

impl RawResultPage {
    /// Pack rows with their verified availability statuses under the control
    /// response byte cap.
    pub(crate) fn pack(
        &self,
        availabilities: &[ResultAvailability],
    ) -> Result<ResultPage, SubmissionError> {
        if availabilities.len() != self.rows.len() {
            return Err(ErrorCode::StoreUnavailable.into());
        }
        let mut items: Vec<(i64, ResultSummary)> = self
            .rows
            .iter()
            .zip(availabilities.iter().cloned())
            .map(|(row, availability)| {
                (
                    row.acceptance_sequence,
                    ResultSummary {
                        result_id: row.result_id.clone(),
                        job_id: row.job_id.clone(),
                        attempt_id: row.attempt_id.clone(),
                        published_at_ms: row.published_at_ms,
                        availability,
                    },
                )
            })
            .collect();
        let mut more = self.more;
        let limit = self.response_limit.min(262_144);
        loop {
            let next_cursor = match (more, items.last()) {
                (false, _) => None,
                (true, Some((seq, _))) => Some(self.cursor.after(*seq)?),
                (true, None) => {
                    return Err(CoreError::CapacityExceeded("control_response_bytes").into());
                }
            };
            let page = ResultPage {
                api_version: "1.0".to_owned(),
                result_contract: "rp-0.1".to_owned(),
                items: items.iter().map(|(_, summary)| summary.clone()).collect(),
                next_cursor,
                truncated: more,
            };
            let encoded = serde_json::to_vec(&page)
                .map_err(|_| SubmissionError::from(ErrorCode::StoreUnavailable))?;
            if encoded.len() <= limit {
                decode_result_page(&encoded)
                    .map_err(|_| SubmissionError::from(ErrorCode::StorageIntegrityFault))?;
                return Ok(page);
            }
            if items.pop().is_none() {
                return Err(CoreError::CapacityExceeded("control_response_bytes").into());
            }
            more = true;
        }
    }
}

/// One committed manifest or artifact file record scoped to its creator.
#[derive(Clone, Debug)]
pub(crate) struct StoredResultFile {
    pub(crate) file: CommittedFile,
    pub(crate) filename: String,
    pub(crate) media_type: String,
}

/// Creator-scoped storage usage snapshot from the Store actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreatorStorageUsage {
    pub(crate) retained_input_bytes: u64,
    pub(crate) published_output_bytes: u64,
    pub(crate) private_staging_bytes: u64,
    pub(crate) metadata_bytes: u64,
    pub(crate) measured_at_ms: u64,
}

pub(super) enum ResultReadCommand {
    List(
        AuthContext,
        ResultsQuery,
        SyncSender<Result<RawResultPage, SubmissionError>>,
    ),
    Manifest(
        AuthContext,
        String,
        SyncSender<Result<StoredResultFile, CoreError>>,
    ),
    Artifact(
        AuthContext,
        String,
        SyncSender<Result<StoredResultFile, CoreError>>,
    ),
    Storage(
        AuthContext,
        SyncSender<Result<CreatorStorageUsage, CoreError>>,
    ),
    CheckGrant(AuthContext, &'static str, SyncSender<Result<(), CoreError>>),
}

impl ResultReadCommand {
    pub(super) fn handle(self, db: &Connection, response_limit: usize) {
        match self {
            Self::List(auth, query, reply) => {
                let _ = reply.send(list_results(db, &auth, query, response_limit));
            }
            Self::Manifest(auth, result_id, reply) => {
                let _ = reply.send(read_manifest_file(db, &auth, &result_id));
            }
            Self::Artifact(auth, artifact_id, reply) => {
                let _ = reply.send(read_artifact_file(db, &auth, &artifact_id));
            }
            Self::Storage(auth, reply) => {
                let _ = reply.send(read_storage_usage(db, &auth));
            }
            Self::CheckGrant(auth, grant, reply) => {
                let _ = reply.send(require_active_grant(db, &auth, grant));
            }
        }
    }
}

impl Store {
    pub(crate) fn list_results_raw(
        &self,
        auth: AuthContext,
        query: ResultsQuery,
    ) -> Result<RawResultPage, SubmissionError> {
        self.request(|reply| Command::ResultRead(ResultReadCommand::List(auth, query, reply)))
    }

    pub(crate) fn result_manifest_file(
        &self,
        auth: AuthContext,
        result_id: String,
    ) -> Result<StoredResultFile, CoreError> {
        if !generated_name(&result_id, "res_") {
            return Err(CoreError::NotFound);
        }
        self.request(|reply| {
            Command::ResultRead(ResultReadCommand::Manifest(auth, result_id, reply))
        })
    }

    pub(crate) fn result_artifact_file(
        &self,
        auth: AuthContext,
        artifact_id: String,
    ) -> Result<StoredResultFile, CoreError> {
        if !generated_name(&artifact_id, "art_") {
            return Err(CoreError::NotFound);
        }
        self.request(|reply| {
            Command::ResultRead(ResultReadCommand::Artifact(auth, artifact_id, reply))
        })
    }

    pub(crate) fn creator_storage_usage(
        &self,
        auth: AuthContext,
    ) -> Result<CreatorStorageUsage, CoreError> {
        self.request(|reply| Command::ResultRead(ResultReadCommand::Storage(auth, reply)))
    }

    pub(crate) fn check_active_grant(
        &self,
        auth: AuthContext,
        grant: &'static str,
    ) -> Result<(), CoreError> {
        self.request(|reply| Command::ResultRead(ResultReadCommand::CheckGrant(auth, grant, reply)))
    }
}

fn list_results(
    db: &Connection,
    auth: &AuthContext,
    query: ResultsQuery,
    response_limit: usize,
) -> Result<RawResultPage, SubmissionError> {
    let tx = sql(db.unchecked_transaction())?;
    require_active_grant(&tx, auth, "results.list")?;
    let limit = jobs::page_limit(query.limit)?;
    let cursor = ResultCursor::open(&tx, auth, query.cursor, limit)?;
    let mut base_rows = {
        let mut statement = sql(tx.prepare(
            "SELECT r.result_id,r.job_id,r.attempt_id,r.published_at_ms,j.acceptance_sequence
             FROM results r
             JOIN jobs j USING(job_id)
             WHERE j.client_id=?1
               AND r.publication_sequence<=?2
               AND j.acceptance_sequence>?3
             ORDER BY j.acceptance_sequence ASC
             LIMIT ?4",
        ))?;
        let rows = sql(statement.query_map(
            rusqlite::params![
                auth.client_id.as_str(),
                cursor.publication_high_water,
                cursor.after_acceptance_sequence,
                i64::from(limit) + 1,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        ))?;
        rows.map(sql).collect::<Result<Vec<_>, CoreError>>()?
    };
    let more = base_rows.len() > usize::from(limit);
    base_rows.truncate(usize::from(limit));
    let mut rows = Vec::with_capacity(base_rows.len());
    let mut files_stmt = sql(tx.prepare(
        "SELECT object_name,role,byte_length,sha256 FROM result_files
         WHERE result_id=?1 ORDER BY object_name",
    ))?;
    for (result_id, raw_job_id, attempt_id, published_at_ms, acceptance_sequence) in base_rows {
        let job_id = JobId::parse(raw_job_id).map_err(|_| CoreError::InvalidStore)?;
        let published_at_ms =
            u64::try_from(published_at_ms).map_err(|_| CoreError::InvalidStore)?;
        let file_rows = sql(files_stmt.query_map([&result_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        }))?;
        let mut files = Vec::new();
        for file_row in file_rows {
            let (object_name, role, byte_length, sha256) = sql(file_row)?;
            files.push(CommittedFile {
                object_name,
                role: match role.as_str() {
                    "artifact" => FileRole::Artifact,
                    "manifest" => FileRole::Manifest,
                    _ => return Err(CoreError::InvalidStore.into()),
                },
                byte_length: u64::try_from(byte_length).map_err(|_| CoreError::InvalidStore)?,
                sha256: sha256.try_into().map_err(|_| CoreError::InvalidStore)?,
            });
        }
        rows.push(RawResultRow {
            result_id,
            job_id,
            attempt_id,
            published_at_ms,
            acceptance_sequence,
            files,
        });
    }
    Ok(RawResultPage {
        cursor,
        rows,
        more,
        response_limit,
    })
}

fn read_manifest_file(
    db: &Connection,
    auth: &AuthContext,
    result_id: &str,
) -> Result<StoredResultFile, CoreError> {
    if !generated_name(result_id, "res_") {
        return Err(CoreError::NotFound);
    }
    let tx = sql(db.unchecked_transaction())?;
    require_active_grant(&tx, auth, "results.show")?;
    let row: Option<(String, String, String, i64, Vec<u8>)> = sql(tx
        .query_row(
            "SELECT f.object_name,f.filename,f.media_type,f.byte_length,f.sha256
             FROM results r
             JOIN jobs j USING(job_id)
             JOIN result_files f USING(result_id)
             WHERE r.result_id=?1 AND j.client_id=?2 AND f.role='manifest'",
            rusqlite::params![result_id, auth.client_id.as_str()],
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
    let (object_name, filename, media_type, byte_length, sha256) =
        row.ok_or(CoreError::NotFound)?;
    Ok(StoredResultFile {
        file: CommittedFile {
            object_name,
            role: FileRole::Manifest,
            byte_length: u64::try_from(byte_length).map_err(|_| CoreError::InvalidStore)?,
            sha256: sha256.try_into().map_err(|_| CoreError::InvalidStore)?,
        },
        filename,
        media_type,
    })
}

fn read_artifact_file(
    db: &Connection,
    auth: &AuthContext,
    artifact_id: &str,
) -> Result<StoredResultFile, CoreError> {
    if !generated_name(artifact_id, "art_") {
        return Err(CoreError::NotFound);
    }
    let tx = sql(db.unchecked_transaction())?;
    require_active_grant(&tx, auth, "artifacts.read")?;
    // Joining `results` guarantees uncommitted/private staging files are never
    // exposed through public artifact reads.
    let row: Option<(String, String, String, i64, Vec<u8>)> = sql(tx
        .query_row(
            "SELECT f.object_name,f.filename,f.media_type,f.byte_length,f.sha256
             FROM result_files f
             JOIN results r USING(result_id)
             JOIN jobs j USING(job_id)
             WHERE f.object_name=?1 AND f.role='artifact' AND j.client_id=?2",
            rusqlite::params![artifact_id, auth.client_id.as_str()],
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
    let (object_name, filename, media_type, byte_length, sha256) =
        row.ok_or(CoreError::NotFound)?;
    Ok(StoredResultFile {
        file: CommittedFile {
            object_name,
            role: FileRole::Artifact,
            byte_length: u64::try_from(byte_length).map_err(|_| CoreError::InvalidStore)?,
            sha256: sha256.try_into().map_err(|_| CoreError::InvalidStore)?,
        },
        filename,
        media_type,
    })
}

fn sum_for_client(tx: &Transaction<'_>, query: &str, client_id: &str) -> Result<u64, CoreError> {
    let value: i64 = sql(tx.query_row(query, [client_id], |row| row.get(0)))?;
    u64::try_from(value).map_err(|_| CoreError::InvalidStore)
}

fn read_storage_usage(
    db: &Connection,
    auth: &AuthContext,
) -> Result<CreatorStorageUsage, CoreError> {
    let tx = sql(db.unchecked_transaction())?;
    require_active_grant(&tx, auth, "storage.show")?;
    let client = auth.client_id.as_str();
    let retained_input_bytes = sum_for_client(
        &tx,
        "SELECT coalesce(sum(byte_length),0) FROM captured_inputs
         WHERE client_id=?1
           AND EXISTS (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
        client,
    )?;
    let published_output_bytes = sum_for_client(
        &tx,
        "SELECT coalesce(sum(f.byte_length),0) FROM result_files f
         JOIN publication_allocations a USING(result_id)
         JOIN jobs j USING(job_id)
         WHERE j.client_id=?1 AND a.state='published'",
        client,
    )?;
    let pub_staging = sum_for_client(
        &tx,
        "SELECT coalesce(sum(a.reserved_bytes),0) FROM publication_allocations a
         JOIN jobs j USING(job_id)
         WHERE j.client_id=?1 AND a.state<>'published'",
        client,
    )?;
    let upload_reservations = sum_for_client(
        &tx,
        "SELECT coalesce(sum(declared_length),0) FROM input_upload_reservations
         WHERE client_id=?1",
        client,
    )?;
    let unreferenced_inputs = sum_for_client(
        &tx,
        "SELECT coalesce(sum(byte_length),0) FROM captured_inputs
         WHERE client_id=?1
           AND NOT EXISTS (SELECT 1 FROM job_inputs WHERE job_inputs.input_id=captured_inputs.input_id)",
        client,
    )?;
    let private_staging_bytes = pub_staging
        .checked_add(upload_reservations)
        .and_then(|total| total.checked_add(unreferenced_inputs))
        .ok_or(CoreError::InvalidStore)?;
    let page_count: i64 = sql(tx.pragma_query_value(None, "page_count", |row| row.get(0)))?;
    let page_size: i64 = sql(tx.pragma_query_value(None, "page_size", |row| row.get(0)))?;
    let metadata_bytes = u64::try_from(page_count)
        .ok()
        .and_then(|count| {
            u64::try_from(page_size)
                .ok()
                .and_then(|size| count.checked_mul(size))
        })
        .ok_or(CoreError::InvalidStore)?;
    let measured_at_ms = u64::try_from(now_ms()?).map_err(|_| CoreError::InvalidStore)?;
    Ok(CreatorStorageUsage {
        retained_input_bytes,
        published_output_bytes,
        private_staging_bytes,
        metadata_bytes,
        measured_at_ms,
    })
}
