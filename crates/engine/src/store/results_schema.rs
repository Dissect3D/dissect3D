//! Feature-specific v8 DDL (RP-P02/1), shared by fresh stores and the 7 -> 8
//! upgrade. Additive only: no accepted table, row or reference changes.
//!
//! One allocation per attempt carries the publication identities and the
//! storage charge from before any file is written until either a committed
//! result keeps it or reclamation has durably deleted every file. Prepared
//! content stays private: only a `results` row (written by RP-P03's commit)
//! makes an allocation public, and only an allocation in `prepared` may be
//! committed. Reclamation moves an allocation to `reclaiming` first, so a
//! reclaimed identity can never be published afterwards.
//!
//! `instance_id` fences reclamation against an engine-side preparation that
//! is still running: `preparing` means a preparer may still be writing, so
//! only an allocation from an earlier service session (which restart proved
//! gone) is reclaimable in that state. A preparer whose native work has
//! returned with an error records `failed` itself.
//!
//! File rows are recorded with their exact length and digest before the bytes
//! are written, so every generated private name the engine creates is
//! referenced while it can exist; reconciliation treats any other entry as
//! unexpected. Later features add tables here or in their own file; nothing
//! in this layout assumes a single file per result or a single file format.
use super::*;

pub(super) fn add_result_tables(tx: &Transaction<'_>) -> Result<(), CoreError> {
    tx.execute_batch(
        "CREATE TABLE publication_allocations (
            result_id TEXT PRIMARY KEY
                CHECK(length(result_id)=36 AND substr(result_id,1,4)='res_'),
            publication_id TEXT NOT NULL UNIQUE
                CHECK(length(publication_id)=36 AND substr(publication_id,1,4)='pub_'),
            job_id TEXT NOT NULL REFERENCES job_execution(job_id),
            attempt_id TEXT NOT NULL UNIQUE REFERENCES job_attempts(attempt_id),
            instance_id TEXT NOT NULL REFERENCES service_sessions(instance_id),
            state TEXT NOT NULL
                CHECK(state IN ('preparing','prepared','failed','published','reclaiming')),
            reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes BETWEEN 1 AND 67108864),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>=created_at_ms),
            UNIQUE(result_id,job_id,attempt_id)
         );
         CREATE INDEX publication_allocations_by_state
            ON publication_allocations(state,created_at_ms);
         CREATE TABLE result_files (
            object_name TEXT PRIMARY KEY
                CHECK(length(object_name)=36 AND substr(object_name,1,4) IN ('art_','pub_')),
            result_id TEXT NOT NULL REFERENCES publication_allocations(result_id),
            role TEXT NOT NULL CHECK(role IN ('manifest','artifact')),
            filename TEXT NOT NULL CHECK(length(filename) BETWEEN 1 AND 255),
            media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
            byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 67108864),
            sha256 BLOB NOT NULL CHECK(length(sha256)=32),
            UNIQUE(result_id,filename COLLATE NOCASE)
         );
         CREATE UNIQUE INDEX result_files_one_manifest
            ON result_files(result_id) WHERE role='manifest';
         CREATE TABLE results (
            result_id TEXT PRIMARY KEY REFERENCES publication_allocations(result_id),
            job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id),
            attempt_id TEXT NOT NULL UNIQUE REFERENCES job_attempts(attempt_id),
            publication_sequence INTEGER NOT NULL UNIQUE CHECK(publication_sequence>=1),
            manifest_version TEXT NOT NULL CHECK(length(manifest_version) BETWEEN 1 AND 16),
            published_at_ms INTEGER NOT NULL CHECK(published_at_ms>=0),
            FOREIGN KEY(result_id,job_id,attempt_id)
                REFERENCES publication_allocations(result_id,job_id,attempt_id)
         );
         CREATE TABLE publication_sequence (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            value INTEGER NOT NULL CHECK(value>=0)
         );
         INSERT INTO publication_sequence(singleton,value) VALUES(1,0);",
    )
    .map_err(|_| CoreError::StoreUnavailable)
}

/// Returns a v8 store to its v7 shape, for tests that seed older versions.
#[cfg(test)]
pub(crate) const DROP_V8_TABLES: &str = "DROP TABLE results; DROP TABLE result_files; \
     DROP TABLE publication_allocations; DROP TABLE publication_sequence;";
