use super::*;
use dissect3d_platform::{AuthorityLease, RootPurpose};
use std::time::Duration;

fn injected_migration_failure(_: &Transaction<'_>) -> Result<(), CoreError> {
    Err(CoreError::StoreUnavailable)
}

fn add_temporary_migration_table(transaction: &Transaction<'_>) -> Result<(), CoreError> {
    transaction
        .execute_batch("CREATE TABLE temporary_migration_probe(value INTEGER);")
        .map_err(|_| CoreError::StoreUnavailable)
}

#[cfg(unix)]
#[test]
fn migrations_execute_under_required_connection_safety_policy() {
    fn checked_migration(transaction: &Transaction<'_>) -> Result<(), CoreError> {
        verify_pragmas(transaction)?;
        add_internal_shutdown_table(transaction)
    }
    let temp = tempfile::tempdir().unwrap();
    let root =
        OwnedRoot::create_private(&temp.path().join("engine"), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    drop(store);
    let root = OwnedRoot::open(&temp.path().join("engine"), RootPurpose::EngineData).unwrap();
    let path = root.path_for_native_vfs(&RelativePath::parse(DATABASE_NAME).unwrap());
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("DROP TABLE results; DROP TABLE result_files; DROP TABLE publication_allocations; DROP TABLE publication_sequence; DROP TABLE job_events; DROP TABLE resource_reservations; DROP TABLE job_attempts; DROP TABLE retry_bindings; DROP TABLE job_execution; DROP TABLE client_authorizations; DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs; DROP TABLE input_upload_reservations; DROP TABLE internal_shutdowns; ALTER TABLE credentials DROP COLUMN grant_policy; PRAGMA user_version=1;")
        .unwrap();
    drop(connection);
    let _lease = AuthorityLease::acquire(&root).unwrap();
    let registry = [
        MigrationStep {
            from: 1,
            to: 2,
            apply: checked_migration,
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
    assert!(open_database_with_migrations(&root, &CorePolicy::default(), &registry).is_ok());
}

#[cfg(unix)]
#[test]
fn locked_sqlite_open_flag_rejects_a_symlinked_filename() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("temporary directory");
    let canonical = std::fs::canonicalize(directory.path()).expect("canonical directory");
    let target = canonical.join("target.sqlite3");
    let link = canonical.join("linked.sqlite3");
    let original = b"target bytes";
    std::fs::write(&target, original).expect("target database bytes");
    symlink(&target, &link).expect("sqlite filename symlink");

    assert!(matches!(
        open_internal_database(&link),
        Err(CoreError::StoreUnavailable)
    ));
    assert_eq!(
        std::fs::read(target).expect("target after SQLite refusal"),
        original
    );
}

#[test]
fn failed_initialization_rolls_back_file_backed_schema_and_markers() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("rollback.sqlite3");
    let mut connection = Connection::open(path).expect("file-backed database");
    connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .expect("sqlite policy");

    assert_eq!(
        initialize_schema_with_hook(&mut connection, || Err(CoreError::StoreUnavailable)),
        Err(CoreError::StoreUnavailable)
    );
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .expect("application marker");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("schema version");
    let table_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table'",
            [],
            |row| row.get(0),
        )
        .expect("schema table count");
    assert_eq!(application_id, 0);
    assert_eq!(version, 0);
    assert_eq!(table_count, 0);
}

#[test]
fn native_signal_shutdown_has_a_durable_identity_and_restart_marks_it_interrupted() {
    let mut connection = Connection::open_in_memory().expect("in-memory metadata");
    initialize_schema(&mut connection).expect("initial schema");
    let identity = read_identity(&connection).expect("service identity");
    let operation_id = signal_shutdown(&mut connection, identity.instance_id.clone())
        .expect("signal intent commit");
    let phase: String = connection
        .query_row(
            "SELECT phase FROM internal_shutdowns WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .expect("durable signal operation");
    assert_eq!(phase, "quiescing");

    // The next owner reconciles a process that died before the final barrier.
    initialize_schema(&mut connection).expect("startup recovery");
    let (state, phase): (String, String) = connection
        .query_row(
            "SELECT state,phase FROM internal_shutdowns WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("recovered signal operation");
    assert_eq!(
        (state.as_str(), phase.as_str()),
        ("interrupted", "interrupted")
    );
}

#[test]
fn native_signal_shutdown_completion_commits_its_internal_operation() {
    let mut connection = Connection::open_in_memory().expect("in-memory metadata");
    initialize_schema(&mut connection).expect("initial schema");
    let identity = read_identity(&connection).expect("service identity");
    let operation_id = signal_shutdown(&mut connection, identity.instance_id.clone())
        .expect("signal intent commit");
    complete_shutdown(&mut connection, identity.instance_id).expect("shutdown barrier");
    let (state, phase): (String, String) = connection
        .query_row(
            "SELECT state,phase FROM internal_shutdowns WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("completed signal operation");
    assert_eq!(
        (state.as_str(), phase.as_str()),
        ("succeeded", "shutdown_committed")
    );
}

#[test]
fn native_signal_reuses_an_already_accepted_api_shutdown_coordinator() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("signal-race-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let (shutdown_sender, mut shutdown_receiver) = tokio::sync::mpsc::unbounded_channel();
    let store =
        Store::open_with_shutdown(root, lease, &CorePolicy::default(), Some(shutdown_sender))
            .expect("coordinated store");
    let identity = store.identity().expect("service identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client");
    let enrollment_id = dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
        .expect("enrollment");
    let secret = [87_u8; 32];
    let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        ))
        .expect("enroll stop client");
    let context = store
        .authenticate(client_id, digest)
        .expect("active stop grant");
    store
        .request_shutdown(
            context,
            identity.instance_id.clone(),
            IdempotencyKey::parse("signal-race-api-key-1").expect("idempotency key"),
        )
        .expect("API shutdown acceptance");
    let accepted_deadline = shutdown_receiver
        .try_recv()
        .expect("accepted API shutdown woke coordinator");
    let signal_deadline = store
        .signal_shutdown(identity.instance_id, 5_000)
        .expect("native signal reuses active coordinator");
    assert_eq!(signal_deadline, accepted_deadline);
    drop(store);

    let database = Connection::open(path.join(DATABASE_NAME)).expect("metadata database");
    let internal_rows: i64 = database
        .query_row("SELECT count(*) FROM internal_shutdowns", [], |row| {
            row.get(0)
        })
        .expect("internal signal operations");
    assert_eq!(internal_rows, 0, "the race must not create a second intent");
}

#[test]
fn failed_migration_keeps_consistent_backup_and_original_store() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("migration-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("create v1 store");
    drop(store);

    let root = OwnedRoot::open(&path, RootPurpose::EngineData).expect("reopen root");
    let _lease = AuthorityLease::acquire(&root).expect("reacquire authority");
    let mut connection = Connection::open(path.join(DATABASE_NAME)).expect("open v1");
    let migrations = [
        MigrationStep {
            from: SCHEMA_VERSION,
            to: SCHEMA_VERSION + 1,
            apply: add_temporary_migration_table,
        },
        MigrationStep {
            from: SCHEMA_VERSION + 1,
            to: SCHEMA_VERSION + 2,
            apply: injected_migration_failure,
        },
    ];
    assert_eq!(
        run_migrations(&mut connection, &root, &migrations),
        Err(CoreError::StoreUnavailable)
    );
    let original_version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("original version");
    assert_eq!(original_version, SCHEMA_VERSION);
    let temporary_table_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='temporary_migration_probe'",
            [],
            |row| row.get(0),
        )
        .expect("migration table count");
    assert_eq!(temporary_table_count, 0);

    let backup_name = recovery_backup_for_version(SCHEMA_VERSION + 2).unwrap();
    let backup_path = root.path_for_native_vfs(&backup_name);
    assert!(
        root.file_metadata(&backup_name)
            .expect("protected backup")
            .length
            > 0
    );
    let backup = Connection::open(backup_path).expect("retained backup");
    let integrity: String = backup
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("backup integrity");
    assert_eq!(integrity, "ok");
    let backup_version: i64 = backup
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("backup version");
    assert_eq!(backup_version, SCHEMA_VERSION);
}

#[test]
fn schema_v1_store_migrates_additively_before_shutdown_recovery() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root_path = directory.path().join("legacy-root");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("protected root");
    let lease = AuthorityLease::acquire(&root).expect("initial authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("initial store");
    let identity = store.identity().expect("initial identity");
    drop(store);

    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("reopen root");
    let database_path =
        root.path_for_native_vfs(&RelativePath::parse(DATABASE_NAME).expect("database path"));
    let connection = Connection::open(&database_path).expect("legacy database");
    assert_eq!(
        read_identity(&connection).expect("legacy identity"),
        identity
    );
    connection
        .execute_batch(
            "DROP TABLE results; DROP TABLE result_files; DROP TABLE publication_allocations; DROP TABLE publication_sequence; DROP TABLE job_events; DROP TABLE resource_reservations; DROP TABLE job_attempts; DROP TABLE retry_bindings; DROP TABLE job_execution; DROP TABLE client_authorizations; DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs;
                 DROP TABLE input_upload_reservations;
                 DROP TABLE internal_shutdowns;
                 ALTER TABLE credentials DROP COLUMN grant_policy;
                 PRAGMA user_version=1;",
        )
        .expect("shape schema-v1 fixture");
    drop(connection);

    let lease = AuthorityLease::acquire(&root).expect("legacy authority");
    let store = Store::open(root, lease, &CorePolicy::default())
        .expect("production startup migrates before recovery");
    let migrated_identity = store.identity().expect("migrated identity");
    drop(store);

    let connection = Connection::open(&database_path).expect("migrated database");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("migrated version");
    assert_eq!(version, SCHEMA_VERSION);
    assert_eq!(migrated_identity.installation_id, identity.installation_id);
    assert_ne!(migrated_identity.instance_id, identity.instance_id);
    assert_eq!(
        read_identity(&connection).expect("recovered identity"),
        migrated_identity
    );
    let table_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='internal_shutdowns'",
            [],
            |row| row.get(0),
        )
        .expect("internal shutdown table");
    assert_eq!(table_count, 1);
    let backup = root_path.join(
        recovery_backup_for_version(SCHEMA_VERSION)
            .unwrap()
            .as_str(),
    );
    let backup = Connection::open(backup).expect("retained v1 recovery backup");
    let backup_version: i64 = backup
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("backup version");
    assert_eq!(backup_version, 1);
}

#[test]
fn shutdown_request_is_durable_idempotent_and_bound_to_its_instance() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("shutdown-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
    let identity = store.identity().expect("identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
    let enrollment_id = dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
        .expect("enrollment id");
    let secret = [73_u8; 32];
    let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        ))
        .expect("enroll stop client");
    let context = store
        .authenticate(client_id, digest)
        .expect("active stop grant");
    let key = IdempotencyKey::parse("stop-test-key-0001").expect("idempotency key");
    let accepted = store
        .request_shutdown(context.clone(), identity.instance_id.clone(), key.clone())
        .expect("durably accepted stop");
    assert!(!accepted.replayed);
    assert_eq!(accepted.state, OperationState::Queued);
    assert_eq!(
        store
            .show_operation(context.clone(), accepted.operation_id.clone())
            .expect("accepted operation phase")
            .phase,
        "running"
    );
    assert_eq!(store.revoke_self(context.clone()), Err(CoreError::Busy));

    let replayed = store
        .request_shutdown(context.clone(), identity.instance_id.clone(), key.clone())
        .expect("exact replay");
    assert!(replayed.replayed);
    assert_eq!(replayed.operation_id, accepted.operation_id);
    assert_eq!(replayed.accepted_at_ms, accepted.accepted_at_ms);

    let other_instance =
        InstanceId::parse("eng_ffffffffffffffffffffffffffffffff").expect("other instance");
    assert_eq!(
        store.request_shutdown(context.clone(), other_instance, key.clone()),
        Err(CoreError::Conflict)
    );

    // Closing the actor without the completion barrier exercises restart
    // reconciliation in-process; abrupt process death is covered only by
    // the test-owned lifecycle process acceptance.
    drop(store);

    let root = OwnedRoot::open(&path, RootPurpose::EngineData).expect("reopen root");
    let lease = AuthorityLease::acquire(&root).expect("reopened authority");
    let restarted = Store::open(root, lease, &CorePolicy::default()).expect("restart store");
    let current = restarted.identity().expect("new instance");
    assert_ne!(current.instance_id, identity.instance_id);
    let restarted_context = restarted
        .authenticate(
            ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id"),
            TokenDigest::new(sha2::Sha256::digest(secret).into()),
        )
        .expect("credential survives restart");
    let old_operation = restarted
        .request_shutdown(
            restarted_context.clone(),
            identity.instance_id.clone(),
            key.clone(),
        )
        .expect("old instance replay");
    assert_eq!(old_operation.state, OperationState::Interrupted);
    assert!(old_operation.replayed);
    assert_eq!(
        restarted.request_shutdown(restarted_context.clone(), current.instance_id.clone(), key,),
        Err(CoreError::Conflict)
    );
    let current_key = IdempotencyKey::parse("stop-test-key-0002").expect("current key");
    let accepted_current = restarted
        .request_shutdown(
            restarted_context.clone(),
            current.instance_id.clone(),
            current_key.clone(),
        )
        .expect("new instance has a new operation");
    assert!(!accepted_current.replayed);
    restarted
        .complete_shutdown(current.instance_id.clone())
        .expect("current instance shutdown completion");
    let committed = restarted
        .show_operation(
            restarted_context.clone(),
            accepted_current.operation_id.clone(),
        )
        .expect("committed shutdown phase");
    assert_eq!(committed.phase, "shutdown_committed");
    let completed = restarted
        .request_shutdown(restarted_context, current.instance_id, current_key)
        .expect("completed request replay");
    assert_eq!(completed.state, OperationState::Succeeded);
    assert!(completed.replayed);
    drop(restarted);
}

#[test]
fn shutdown_fingerprint_uses_the_accepted_canonical_preimage() {
    let instance = InstanceId::parse("eng_0123456789abcdef0123456789abcdef").expect("instance id");
    let preimage = format!("core-shutdown-v1\n{}\n", instance.as_str());
    let expected: [u8; 32] = sha2::Sha256::digest(preimage.as_bytes()).into();
    assert_eq!(shutdown_fingerprint(&instance), expected);
}

#[test]
fn operation_history_limit_allows_replay_but_rejects_new_shutdown_rows() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("operation-cap-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
    let identity = store.identity().expect("identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client");
    let enrollment_id = dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
        .expect("enrollment");
    let digest = TokenDigest::new(sha2::Sha256::digest([73_u8; 32]).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        ))
        .expect("enroll");
    let context = store.authenticate(client_id, digest).expect("authenticate");
    let replay_key = IdempotencyKey::parse("operation-cap-replay-01").expect("key");
    let accepted = store
        .request_shutdown(
            context.clone(),
            identity.instance_id.clone(),
            replay_key.clone(),
        )
        .expect("first acceptance");
    store
        .seed_operation_history((MAX_CORE_OPERATION_ROWS - 1) as usize)
        .expect("fill durable operation history");
    let replay = store
        .request_shutdown(context.clone(), identity.instance_id.clone(), replay_key)
        .expect("exact replay at capacity");
    assert!(replay.replayed);
    assert_eq!(replay.operation_id, accepted.operation_id);
    assert_eq!(
        store.request_shutdown(
            context,
            identity.instance_id,
            IdempotencyKey::parse("operation-cap-new-key-01").expect("new key"),
        ),
        Err(CoreError::LimitReached),
    );
}

#[test]
fn dropping_shutdown_response_waiter_does_not_strand_committed_intent() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("shutdown-coordinator-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let (intent_sender, mut intent_receiver) = tokio::sync::mpsc::unbounded_channel();
    let store = Store::open_with_shutdown(root, lease, &CorePolicy::default(), Some(intent_sender))
        .expect("store with engine coordinator");
    let identity = store.identity().expect("identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
    let enrollment_id = dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
        .expect("enrollment id");
    let digest = TokenDigest::new(sha2::Sha256::digest([73_u8; 32]).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        ))
        .expect("enroll stop client");
    let context = store.authenticate(client_id, digest).expect("active grant");
    let key = IdempotencyKey::parse("shutdown-cancel-window-1").expect("shutdown key");

    // Hold the actor immediately before transactional acceptance so the
    // response waiter disappears while the commit is still in flight.
    let (started_sender, started_receiver) = mpsc::sync_channel(1);
    let (release_sender, release_receiver) = mpsc::sync_channel(1);
    let (configured_sender, configured_receiver) = mpsc::sync_channel(1);
    store
        .sender
        .send(Command::PauseNextShutdown(
            started_sender,
            release_receiver,
            configured_sender,
        ))
        .expect("configure internal acceptance barrier");
    configured_receiver
        .recv()
        .expect("actor installed internal acceptance barrier");

    // This dropped reply models HTTP task cancellation. The synchronous
    // actor command remains owned by the engine and finishes its commit.
    let (receipt_sender, receipt_receiver) = mpsc::sync_channel(1);
    store
        .sender
        .try_send(Command::Shutdown(
            context.clone(),
            identity.instance_id.clone(),
            key.clone(),
            receipt_sender,
        ))
        .expect("queue shutdown acceptance");
    started_receiver
        .recv()
        .expect("actor paused during shutdown acceptance");
    drop(receipt_receiver);
    release_sender
        .send(())
        .expect("release internal acceptance barrier");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let first_deadline = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), intent_receiver.recv())
            .await
            .expect("committed shutdown wakes the coordinator")
            .expect("coordinator remains alive")
    });

    let replay = store
        .request_shutdown(context.clone(), identity.instance_id.clone(), key)
        .expect("exact queued replay");
    assert!(replay.replayed);
    assert_eq!(replay.state, OperationState::Running);
    let snapshot = store
        .show_operation(context, replay.operation_id.clone())
        .expect("operation snapshot");
    assert_eq!(snapshot.state, OperationState::Running);
    assert_eq!(snapshot.phase, "quiescing");
    let replay_deadline = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), intent_receiver.recv())
            .await
            .expect("queued replay re-arms coordinator")
            .expect("coordinator remains alive")
    });
    assert_eq!(
        replay_deadline, first_deadline,
        "replay must not reset shutdown budget"
    );
}

#[test]
fn injected_sqlite_page_limit_returns_failure_without_committing_partial_enrollment() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("limited-store");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
    let identity = store.identity().expect("identity");
    let owner = current_owner_identity().expect("owner");
    store
        .limit_database_pages_to_current_plus_one()
        .expect("test-only SQLite page limit");

    let mut failed = None;
    for index in 0..2_048_u32 {
        let client_id = ClientId::parse(format!("cli_{index:032x}")).expect("test client identity");
        let enrollment_id = dissect3d_api::EnrollmentId::parse(format!("enr_{index:032x}"))
            .expect("test enrollment identity");
        let digest = TokenDigest::new([index as u8; 32]);
        match store.enroll(VerifiedEnrollment::new(
            owner.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        )) {
            Ok(_) => {}
            Err(CoreError::StoreUnavailable) => {
                failed = Some((client_id, digest));
                break;
            }
            Err(error) => panic!("unexpected injected page-limit result: {error:?}"),
        }
    }
    let (client_id, digest) = failed.expect("SQLite page limit must be reached");
    assert!(matches!(
        store.authenticate(client_id, digest),
        Err(CoreError::Unauthorized)
    ));
    drop(store);

    let database = Connection::open(path.join(DATABASE_NAME)).expect("SQLite database");
    let integrity: String = database
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check");
    assert_eq!(integrity, "ok");
}

#[test]
fn injected_shutdown_precommit_failure_returns_no_receipt_and_allows_exact_retry() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("shutdown-fault-root");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("store");
    let identity = store.identity().expect("identity");
    let client_id = ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id");
    let enrollment_id = dissect3d_api::EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef")
        .expect("enrollment id");
    let secret = [73_u8; 32];
    let digest = TokenDigest::new(sha2::Sha256::digest(secret).into());
    store
        .enroll(VerifiedEnrollment::new(
            current_owner_identity().expect("owner"),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            enrollment_id,
            client_id.clone(),
            digest.clone(),
        ))
        .expect("enroll stop client");
    let context = store
        .authenticate(client_id, digest)
        .expect("active shutdown grant");
    let key = IdempotencyKey::parse("shutdown-fault-key-01").expect("shutdown key");
    store
        .fail_next_shutdown_commit()
        .expect("arm one-shot precommit failure");

    assert!(matches!(
        store.request_shutdown(context.clone(), identity.instance_id.clone(), key.clone()),
        Err(CoreError::StoreUnavailable)
    ));
    let accepted = store
        .request_shutdown(context, identity.instance_id.clone(), key)
        .expect("exact retry after rolled-back transaction");
    assert!(!accepted.replayed);
    assert_eq!(accepted.state, OperationState::Queued);
    drop(store);

    let database = Connection::open(path.join(DATABASE_NAME)).expect("SQLite database");
    let count: i64 = database
        .query_row(
            "SELECT count(*) FROM core_operations WHERE kind='engine.shutdown'",
            [],
            |row| row.get(0),
        )
        .expect("operation count");
    assert_eq!(count, 1, "failed transaction must leave no duplicate row");
    let integrity: String = database
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity check");
    assert_eq!(integrity, "ok");
}
