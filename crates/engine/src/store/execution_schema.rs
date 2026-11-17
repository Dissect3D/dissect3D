//! Feature-specific v7 DDL, shared by fresh stores and supported upgrades.
use super::*;

pub(super) fn add_execution_tables(tx: &Transaction<'_>) -> Result<(), CoreError> {
    tx.execute_batch(
        "CREATE TABLE job_execution (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
            snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision>=1),
            state TEXT NOT NULL CHECK(state IN ('queued','running','cancel_requested','succeeded','partial','failed','canceled','interrupted')),
            phase TEXT NOT NULL CHECK(length(phase) BETWEEN 1 AND 64),
            progress_json TEXT,
            timeout_ms INTEGER CHECK(timeout_ms BETWEEN 1 AND 86400000),
            cancel_requested_at_ms INTEGER,
            cleanup_status TEXT NOT NULL CHECK(cleanup_status IN ('pending','confirmed','fault')),
            cleanup_reason TEXT,
            outcome_code TEXT,
            retry_of TEXT REFERENCES jobs(job_id),
            updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE job_attempts (
            attempt_id TEXT PRIMARY KEY,
            job_id TEXT UNIQUE NOT NULL REFERENCES job_execution(job_id),
            instance_id TEXT NOT NULL REFERENCES service_sessions(instance_id),
            session_id TEXT UNIQUE NOT NULL,
            grant_id TEXT UNIQUE NOT NULL,
            dispatched_at_ms INTEGER NOT NULL,
            native_identity_json TEXT,
            cleanup_status TEXT NOT NULL CHECK(cleanup_status IN ('pending','confirmed','fault'))
         );
         CREATE TABLE resource_reservations (
            attempt_id TEXT NOT NULL REFERENCES job_attempts(attempt_id),
            resource_id TEXT NOT NULL CHECK(length(resource_id) BETWEEN 1 AND 128),
            released INTEGER NOT NULL DEFAULT 0 CHECK(released IN (0,1)),
            PRIMARY KEY(attempt_id,resource_id)
         );
         CREATE UNIQUE INDEX resource_reservation_exclusive ON resource_reservations(resource_id) WHERE released=0;
         CREATE TABLE job_events (
            job_id TEXT NOT NULL REFERENCES job_execution(job_id),
            snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision>=1),
            snapshot_json TEXT NOT NULL CHECK(length(snapshot_json)<=16384),
            PRIMARY KEY(job_id,snapshot_revision)
         );
         CREATE TABLE retry_bindings (
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            idempotency_key TEXT NOT NULL,
            source_job_id TEXT NOT NULL REFERENCES jobs(job_id),
            retry_job_id TEXT UNIQUE NOT NULL REFERENCES jobs(job_id),
            PRIMARY KEY(client_id,idempotency_key)
         );
         CREATE TABLE client_authorizations (
            authorization_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            grant_policy TEXT NOT NULL CHECK(grant_policy='execution-v1'),
            created_at_ms INTEGER NOT NULL
         );
         CREATE INDEX client_authorizations_client ON client_authorizations(client_id);
         CREATE TABLE submission_bindings_v7 (
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            operation TEXT NOT NULL CHECK(operation='jobs.submit'),
            idempotency_key TEXT NOT NULL,
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            canonicalization_version INTEGER NOT NULL CHECK(canonicalization_version IN (1,2)),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            original_inputs_json TEXT NOT NULL,
            PRIMARY KEY(client_id,operation,idempotency_key)
         );
         INSERT INTO submission_bindings_v7 SELECT * FROM submission_bindings;
         DROP TABLE submission_bindings;
         ALTER TABLE submission_bindings_v7 RENAME TO submission_bindings;
         INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms)
             SELECT job_id,1,'queued','queued','confirmed',created_at_ms FROM jobs;"
    ).map_err(|_| CoreError::StoreUnavailable)
}
