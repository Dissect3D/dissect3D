//! Database open, connection pragmas, schema initialization, migrations and
//! verified recovery backups.

use super::*;

pub(super) fn protected_sqlite_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW
}

pub(super) fn open_internal_database(path: &Path) -> Result<Connection, CoreError> {
    Connection::open_with_flags(path, protected_sqlite_open_flags())
        .map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn open_database(
    root: &OwnedRoot,
    policy: &CorePolicy,
) -> Result<Connection, CoreError> {
    open_database_with_migrations(root, policy, &CORE_MIGRATIONS)
}

pub(super) fn open_database_with_migrations(
    root: &OwnedRoot,
    policy: &CorePolicy,
    migrations: &[MigrationStep],
) -> Result<Connection, CoreError> {
    let database = RelativePath::parse(DATABASE_NAME).map_err(CoreError::Platform)?;
    let existing = match root.file_metadata(&database) {
        Ok(metadata) => Some(metadata.length),
        Err(PlatformError::NotFound) => None,
        Err(error) => return Err(CoreError::Platform(error)),
    };
    if existing.is_none() {
        root.write_atomic(&database, &[])
            .map_err(CoreError::Platform)?;
    }
    let path: PathBuf = root.path_for_native_vfs(&database);
    // The platform layer creates and validates this fixed file first. Keep
    // SQLite's standard VFS, disable URI interpretation, and ask SQLite to
    // reject a final-component symlink if the pathname changes before open.
    // This is defense in depth inside a protected per-user root, not a claim
    // that every SQLite operation is bound to the validated directory handle.
    let mut connection = open_internal_database(&path)?;
    connection
        .set_limit(
            limits::Limit::SQLITE_LIMIT_LENGTH,
            policy.maximum_value_bytes as i32,
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(
            policy.busy_timeout_ms.into(),
        ))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let app_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let schema_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Inspect existing markers and journal mode before writable initialization
    // PRAGMAs. A future/foreign database must be rejected without mutating it.
    if existing.is_some_and(|length| length != 0) {
        if app_id != APPLICATION_ID || schema_version > SCHEMA_VERSION {
            return Err(CoreError::StoreIncompatible);
        }
        let current_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        if !current_mode.eq_ignore_ascii_case("wal") {
            return Err(CoreError::StoreIncompatible);
        }
    }
    configure_connection(&connection)?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(CoreError::StoreIncompatible);
    }
    if existing.is_some_and(|length| length != 0) {
        run_migrations(&mut connection, root, migrations)?;
    }
    initialize_schema(&mut connection)?;
    verify_pragmas(&connection)?;
    Ok(connection)
}

pub(super) fn configure_connection(connection: &Connection) -> Result<(), CoreError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;
             PRAGMA synchronous=FULL;
             PRAGMA wal_autocheckpoint=256;
             PRAGMA journal_size_limit=4194304;",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    #[cfg(target_os = "macos")]
    connection
        .execute_batch("PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON;")
        .map_err(|_| CoreError::StoreUnavailable)?;
    verify_pragmas(connection)
}

pub(super) fn initialize_schema(connection: &mut Connection) -> Result<(), CoreError> {
    initialize_schema_with_hook(connection, || Ok(()))
}

pub(super) fn initialize_schema_with_hook(
    connection: &mut Connection,
    before_commit: impl FnOnce() -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let app_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if app_id == APPLICATION_ID && version == SCHEMA_VERSION {
        // A new actor owns the exclusive lease, so prior active sessions cannot
        // still be serving requests. Record their loss and interrupt accepted
        // work in the same transaction that creates this session.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .execute(
                "UPDATE service_sessions SET termination='unclean', ended_at_ms=?1
                 WHERE termination='active'",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        before_commit()?;
        transaction
            .execute(
                "UPDATE core_operations SET state='interrupted', updated_at_ms=?1,
                 phase='interrupted' WHERE state IN ('queued','running')",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .execute(
                "UPDATE internal_shutdowns SET state='interrupted', phase='interrupted', updated_at_ms=?1
                 WHERE state IN ('queued','running')",
                [now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        execution::interrupt_active(&transaction)?;
        let instance = new_instance_id()?;
        transaction
            .execute(
                "INSERT INTO service_sessions(instance_id,started_at_ms,ended_at_ms,termination)
                 VALUES(?1,?2,NULL,'active')",
                rusqlite::params![instance.as_str(), now_ms()?],
            )
            .map_err(|_| CoreError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| CoreError::StoreUnavailable)?;
        return Ok(());
    }
    if app_id != 0 || version != 0 {
        return Err(CoreError::StoreIncompatible);
    }
    let installation = new_installation_id()?;
    let instance = new_instance_id()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Schema and its SQLite ownership/version markers commit together; a crash
    // cannot advertise a version whose tables were only partly created.
    transaction
        .execute_batch(
            "CREATE TABLE engine_identity (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                installation_id TEXT UNIQUE NOT NULL,
                created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE service_sessions (
                instance_id TEXT PRIMARY KEY,
                started_at_ms INTEGER NOT NULL,
                ended_at_ms INTEGER,
                termination TEXT NOT NULL CHECK(termination IN ('active','clean','unclean'))
             );
             CREATE TABLE credentials (
                client_id TEXT PRIMARY KEY,
                enrollment_id TEXT UNIQUE NOT NULL,
                secret_digest BLOB NOT NULL CHECK(length(secret_digest)=32),
                client_kind TEXT NOT NULL CHECK(client_kind='cli'),
                grant_policy TEXT NOT NULL DEFAULT 'core-v1'
                    CHECK(grant_policy IN ('core-v1','submission-v1')),
                created_at_ms INTEGER NOT NULL,
                revoked_at_ms INTEGER
             );
             CREATE TABLE credential_grants (
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                operation TEXT NOT NULL,
                PRIMARY KEY(client_id,operation)
             );
             CREATE TABLE core_operations (
                operation_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                idempotency_key TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind='engine.shutdown'),
                instance_id TEXT NOT NULL REFERENCES service_sessions(instance_id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                error_code TEXT,
                UNIQUE(client_id,kind,idempotency_key)
             );
             CREATE TABLE internal_shutdowns (
                operation_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL UNIQUE REFERENCES service_sessions(instance_id),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );
             CREATE TABLE input_upload_reservations (
                reservation_id TEXT PRIMARY KEY,
                input_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                declared_length INTEGER NOT NULL CHECK(declared_length BETWEEN 1 AND 268435456),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                created_at_ms INTEGER NOT NULL
             );
             CREATE INDEX input_upload_reservations_owner
                ON input_upload_reservations(client_id,created_at_ms);
             CREATE TABLE captured_inputs (
                input_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 268435456),
                sha256 BLOB NOT NULL CHECK(length(sha256)=32),
                completed_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>completed_at_ms),
                cleanup_state TEXT NOT NULL DEFAULT 'complete'
                    CHECK(cleanup_state IN ('complete','deleting'))
             );
             CREATE INDEX captured_inputs_owner_expiry
                ON captured_inputs(client_id,expires_at_ms);
             CREATE TABLE engine_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>=0)
             );
             ",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    add_job_tables(&transaction)?;
    add_execution_tables(&transaction)?;
    add_result_tables(&transaction)?;
    transaction
        .execute(
            "INSERT INTO engine_clock(singleton,last_observed_ms) VALUES(1,?1)",
            [now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT INTO engine_identity(singleton,installation_id,created_at_ms)
             VALUES(1,?1,?2)",
            rusqlite::params![installation.as_str(), now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT INTO service_sessions(instance_id,started_at_ms,termination)
             VALUES(?1,?2,'active')",
            rusqlite::params![instance.as_str(), now_ms()?],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(|_| CoreError::StoreUnavailable)?;
    before_commit()?;
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

pub(super) fn verify_pragmas(connection: &Connection) -> Result<(), CoreError> {
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let trusted_schema: i64 = connection
        .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let wal_autocheckpoint: i64 = connection
        .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let journal_size_limit: i64 = connection
        .query_row("PRAGMA journal_size_limit", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    #[cfg(target_os = "macos")]
    let mac_fullsync = {
        let fullfsync: i64 = connection
            .query_row("PRAGMA fullfsync", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        let checkpoint_fullfsync: i64 = connection
            .query_row("PRAGMA checkpoint_fullfsync", [], |row| row.get(0))
            .map_err(|_| CoreError::StoreUnavailable)?;
        fullfsync == 1 && checkpoint_fullfsync == 1
    };
    #[cfg(not(target_os = "macos"))]
    let mac_fullsync = true;
    if foreign_keys == 1
        && trusted_schema == 0
        && synchronous == 2
        && wal_autocheckpoint == 256
        && journal_size_limit == 4_194_304
        && mac_fullsync
    {
        Ok(())
    } else {
        Err(CoreError::StoreIncompatible)
    }
}

pub(super) struct MigrationStep {
    pub(super) from: i64,
    pub(super) to: i64,
    pub(super) apply: fn(&Transaction<'_>) -> Result<(), CoreError>,
}

pub(super) const CORE_MIGRATIONS: [MigrationStep; 7] = [
    MigrationStep {
        from: 1,
        to: 2,
        apply: add_internal_shutdown_table,
    },
    MigrationStep {
        from: 2,
        to: 3,
        apply: add_credential_grant_policy,
    },
    MigrationStep {
        from: 3,
        to: 4,
        apply: add_input_capture_tables,
    },
    MigrationStep {
        from: 4,
        to: 5,
        apply: add_input_cleanup_state,
    },
    MigrationStep {
        from: 5,
        to: 6,
        apply: add_job_tables,
    },
    MigrationStep {
        from: 6,
        to: 7,
        apply: add_execution_tables,
    },
    MigrationStep {
        from: 7,
        to: 8,
        apply: add_result_tables,
    },
];

pub(super) fn add_internal_shutdown_table(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "CREATE TABLE internal_shutdowns (
                operation_id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL UNIQUE REFERENCES service_sessions(instance_id),
                state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','interrupted')),
                phase TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
             );",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn add_job_tables(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction.execute_batch(
        "CREATE TABLE jobs (
            job_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            acceptance_sequence INTEGER NOT NULL UNIQUE CHECK(acceptance_sequence>0),
            created_at_ms INTEGER NOT NULL,
            resolved_json TEXT NOT NULL,
            storage_status TEXT NOT NULL CHECK(storage_status IN ('verified','storage_integrity_fault'))
         );
         CREATE INDEX jobs_creator_sequence ON jobs(client_id,acceptance_sequence);
         CREATE TABLE submission_bindings (
            client_id TEXT NOT NULL REFERENCES credentials(client_id),
            operation TEXT NOT NULL CHECK(operation='jobs.submit'),
            idempotency_key TEXT NOT NULL,
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            canonicalization_version INTEGER NOT NULL CHECK(canonicalization_version=1),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
            original_inputs_json TEXT NOT NULL,
            PRIMARY KEY(client_id,operation,idempotency_key)
         );
         CREATE TABLE job_inputs (
            job_id TEXT NOT NULL REFERENCES jobs(job_id),
            input_id TEXT NOT NULL REFERENCES captured_inputs(input_id),
            PRIMARY KEY(job_id,input_id)
         );
         CREATE INDEX job_inputs_by_input ON job_inputs(input_id);
         CREATE TABLE job_acceptance_events (
            job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
            acceptance_sequence INTEGER NOT NULL UNIQUE,
            snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision=1)
         );
         CREATE TABLE job_sequence (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            value INTEGER NOT NULL CHECK(value>=0)
         );
         INSERT INTO job_sequence(singleton,value) VALUES(1,0);"
    ).map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn add_credential_grant_policy(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE credentials ADD COLUMN grant_policy TEXT NOT NULL DEFAULT 'core-v1'
             CHECK(grant_policy IN ('core-v1','submission-v1'));",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn add_input_capture_tables(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "CREATE TABLE input_upload_reservations (
                reservation_id TEXT PRIMARY KEY,
                input_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                declared_length INTEGER NOT NULL CHECK(declared_length BETWEEN 1 AND 268435456),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                created_at_ms INTEGER NOT NULL
             );
             CREATE INDEX input_upload_reservations_owner
                ON input_upload_reservations(client_id,created_at_ms);
             CREATE TABLE captured_inputs (
                input_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL REFERENCES credentials(client_id),
                media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
                byte_length INTEGER NOT NULL CHECK(byte_length BETWEEN 1 AND 268435456),
                sha256 BLOB NOT NULL CHECK(length(sha256)=32),
                completed_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>completed_at_ms)
             );
             CREATE INDEX captured_inputs_owner_expiry
                ON captured_inputs(client_id,expires_at_ms);",
        )
        .map_err(|_| CoreError::StoreUnavailable)
}

pub(super) fn add_input_cleanup_state(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch(
            "ALTER TABLE captured_inputs ADD COLUMN cleanup_state TEXT NOT NULL DEFAULT 'complete'
                CHECK(cleanup_state IN ('complete','deleting'));
             CREATE TABLE IF NOT EXISTS engine_clock (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                last_observed_ms INTEGER NOT NULL CHECK(last_observed_ms>=0)
             );",
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    let now = now_ms()?;
    let last_completion: i64 = transaction
        .query_row(
            "SELECT coalesce(max(completed_at_ms),0) FROM captured_inputs",
            [],
            |row| row.get(0),
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    transaction
        .execute(
            "INSERT OR IGNORE INTO engine_clock(singleton,last_observed_ms) VALUES(1,?1)",
            [now.max(last_completion)],
        )
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

/// Apply only a private, contiguous migration registry after retaining a
/// verified online backup. Every step runs with verified durability settings.
pub(super) fn run_migrations(
    connection: &mut Connection,
    root: &OwnedRoot,
    migrations: &[MigrationStep],
) -> Result<(), CoreError> {
    run_migrations_with_backup_at(connection, root, migrations, retain_verified_backup_at)
}

pub(super) fn run_migrations_with_backup_at(
    connection: &mut Connection,
    root: &OwnedRoot,
    migrations: &[MigrationStep],
    retain_backup: impl FnOnce(&Connection, &OwnedRoot, &RelativePath) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let mut version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let mut pending = Vec::new();
    let mut next_version = version;
    // Build and validate the complete contiguous chain before taking a backup
    // or running any migration, so a gap cannot leave a partially upgraded DB.
    while let Some(step) = migrations.iter().find(|step| step.from == next_version) {
        if step.to != next_version + 1 {
            return Err(CoreError::StoreIncompatible);
        }
        pending.push(step);
        next_version = step.to;
    }
    if pending.is_empty() {
        return if version == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(CoreError::StoreIncompatible)
        };
    }
    // Retain a verified pre-upgrade copy before the single transaction changes
    // schema and user_version together.
    let backup_path = recovery_backup_for_version(next_version)?;
    retain_backup(connection, root, &backup_path)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| CoreError::StoreUnavailable)?;
    for step in pending {
        if step.from != version || step.to != version + 1 {
            return Err(CoreError::StoreIncompatible);
        }
        (step.apply)(&transaction)?;
        transaction
            .pragma_update(None, "user_version", step.to)
            .map_err(|_| CoreError::StoreUnavailable)?;
        version = step.to;
    }
    transaction
        .commit()
        .map_err(|_| CoreError::StoreUnavailable)?;
    Ok(())
}

pub(super) fn recovery_backup_for_version(version: i64) -> Result<RelativePath, CoreError> {
    let path = match version {
        3 => RECOVERY_BACKUP.to_owned(),
        4 => RECOVERY_BACKUP_V4.to_owned(),
        5 => RECOVERY_BACKUP_V5.to_owned(),
        8 => RECOVERY_BACKUP_V8.to_owned(),
        _ => format!("recovery/metadata-v{version}-upgrade.sqlite3"),
    };
    RelativePath::parse(path).map_err(CoreError::Platform)
}

pub(super) fn retain_verified_backup_at(
    connection: &Connection,
    root: &OwnedRoot,
    backup_relative: &RelativePath,
) -> Result<(), CoreError> {
    retain_verified_backup_at_with_sync(connection, root, backup_relative, |backup_path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(backup_path)
            .and_then(|file| file.sync_all())
            .map_err(|_| CoreError::StoreUnavailable)
    })
}

pub(super) fn retain_verified_backup_at_with_sync(
    connection: &Connection,
    root: &OwnedRoot,
    backup_relative: &RelativePath,
    sync_backup: impl FnOnce(&Path) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    let existing = root.file_metadata(backup_relative);
    match existing {
        Ok(_) => return Err(CoreError::StoreIncompatible),
        Err(PlatformError::NotFound) => {}
        Err(error) => return Err(CoreError::Platform(error)),
    }
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Refuse an unexpectedly large source rather than consuming unbounded disk
    // during recovery. An existing backup is preserved, never overwritten.
    if page_count < 0
        || page_size < 0
        || page_count.saturating_mul(page_size) > RECOVERY_BACKUP_LIMIT_BYTES
    {
        return Err(CoreError::StoreIncompatible);
    }
    let backup_bytes = page_count.saturating_mul(page_size) as u64;
    let available_bytes = root.available_space_bytes().map_err(CoreError::Platform)?;
    require_recovery_backup_space(available_bytes, backup_bytes)?;
    root.write_atomic(backup_relative, &[])
        .map_err(CoreError::Platform)?;
    let backup_path = root.path_for_native_vfs(backup_relative);
    // The fixed backup file was created through OwnedRoot above; do not let
    // SQLite choose a different URI target or create a missing path itself.
    let mut backup_connection = open_internal_database(&backup_path)?;
    configure_connection(&backup_connection)?;
    let backup = rusqlite::backup::Backup::new(connection, &mut backup_connection)
        .map_err(|_| CoreError::StoreUnavailable)?;
    // SQLite backup can report transient contention between pages; retry only
    // within a fixed budget so startup cannot wait forever on another writer.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match backup.step(64).map_err(|_| CoreError::StoreUnavailable)? {
            rusqlite::backup::StepResult::Done => break,
            rusqlite::backup::StepResult::More => {}
            rusqlite::backup::StepResult::Busy | rusqlite::backup::StepResult::Locked => {
                if std::time::Instant::now() >= deadline {
                    return Err(CoreError::Busy);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => return Err(CoreError::StoreUnavailable),
        }
    }
    drop(backup);
    let integrity: String = backup_connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| CoreError::StoreUnavailable)?;
    if integrity != "ok" {
        return Err(CoreError::InvalidStore);
    }
    backup_connection
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(|_| CoreError::StoreUnavailable)?;
    backup_connection
        .close()
        .map_err(|_| CoreError::StoreUnavailable)?;
    // Windows FlushFileBuffers requires a writable handle; never truncate it.
    sync_backup(&backup_path)?;
    Ok(())
}

pub(super) fn require_recovery_backup_space(
    available_bytes: u64,
    backup_bytes: u64,
) -> Result<(), CoreError> {
    let required = backup_bytes.saturating_add(RECOVERY_BACKUP_FREE_SPACE_FLOOR_BYTES);
    if available_bytes < required {
        Err(CoreError::StoreUnavailable)
    } else {
        Ok(())
    }
}

pub(super) fn read_identity(connection: &Connection) -> Result<StoreIdentity, CoreError> {
    let installation: String = connection
        .query_row(
            "SELECT installation_id FROM engine_identity WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?
        .ok_or(CoreError::InvalidStore)?;
    let instance: String = connection
        .query_row(
            "SELECT instance_id FROM service_sessions WHERE termination='active' ORDER BY started_at_ms DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| CoreError::StoreUnavailable)?
        .ok_or(CoreError::InvalidStore)?;
    Ok(StoreIdentity {
        installation_id: InstallationId::parse(installation)
            .map_err(|_| CoreError::InvalidStore)?,
        instance_id: InstanceId::parse(instance).map_err(|_| CoreError::InvalidStore)?,
    })
}
