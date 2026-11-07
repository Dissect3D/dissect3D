use super::*;
use crate::credentials::{INITIAL_GRANTS, SUBMISSION_GRANTS};
use dissect3d_api::{EnrollmentId, TokenDigest};
use dissect3d_platform::RootPurpose;
use tempfile::{TempDir, tempdir};

const UPGRADE_BACKUP: &str = "recovery/metadata-v6-upgrade.sqlite3";
const LEGACY_BACKUP: &str = "recovery/metadata-upgrade.sqlite3";

#[cfg(unix)]
#[test]
fn upload_reservations_do_not_promise_the_same_free_bytes_twice() {
    let fixture = new_fixture();
    let mut connection = migrate_open(&fixture.root_path).expect("current database");
    let identity = read_identity(&connection).expect("store identity");
    let context = enroll(
        &mut connection,
        VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            identity.installation_id,
            identity.instance_id,
            EnrollmentId::parse("enr_2223456789abcdef0123456789abcdef").unwrap(),
            ClientId::parse("cli_2223456789abcdef0123456789abcdef").unwrap(),
            TokenDigest::new(Sha256::digest([0x33; 32]).into()),
        ),
    )
    .expect("submission credential");
    let context = authenticate(
        &mut connection,
        context.client_id,
        TokenDigest::new(Sha256::digest([0x33; 32]).into()),
    )
    .unwrap();
    let available =
        STORAGE_FREE_RESERVE_BYTES + MAX_INPUT_BYTES + 2 * UPLOAD_METADATA_RESERVE_BYTES;
    reserve_upload(
        &mut connection,
        context.clone(),
        MAX_INPUT_BYTES,
        "application/octet-stream",
        available,
    )
    .expect("first upload reservation");
    assert!(matches!(
        reserve_upload(
            &mut connection,
            context,
            MAX_INPUT_BYTES,
            "application/octet-stream",
            available
        ),
        Err(CoreError::CapacityExceeded("storage_free_reserve_bytes"))
    ));
    let count: i64 = connection
        .query_row(
            "SELECT count(*) FROM input_upload_reservations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "failed admission does not create a reservation");
}

struct CredentialSeed {
    client_id: ClientId,
    enrollment_id: dissect3d_api::EnrollmentId,
    digest: TokenDigest,
}

struct Fixture {
    _parent: TempDir,
    root_path: PathBuf,
    installation_id: InstallationId,
    revoked: CredentialSeed,
    active: CredentialSeed,
}

type CredentialRow = (String, String, Vec<u8>, Option<i64>, String);

fn seed(client: &str, enrollment: &str, byte: u8) -> CredentialSeed {
    CredentialSeed {
        client_id: ClientId::parse(client).expect("client id"),
        enrollment_id: EnrollmentId::parse(enrollment).expect("enrollment id"),
        digest: TokenDigest::new(Sha256::digest([byte; 32]).into()),
    }
}

fn new_fixture() -> Fixture {
    let parent = tempdir().expect("temporary engine root");
    let root_path = parent.path().join("metadata-root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let mut connection = open_database(&root, &CorePolicy::default()).expect("initial store");
    let identity = read_identity(&connection).expect("store identity");
    let owner = current_owner_identity().expect("owner identity");
    let revoked = seed(
        "cli_0123456789abcdef0123456789abcdef",
        "enr_0123456789abcdef0123456789abcdef",
        0x11,
    );
    let active = seed(
        "cli_1123456789abcdef0123456789abcdef",
        "enr_1123456789abcdef0123456789abcdef",
        0x22,
    );
    for credential in [&revoked, &active] {
        enroll(
            &mut connection,
            VerifiedEnrollment::new(
                owner.clone(),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                credential.enrollment_id.clone(),
                credential.client_id.clone(),
                credential.digest.clone(),
            ),
        )
        .expect("core-only enrollment");
    }
    let context = authenticate(
        &mut connection,
        revoked.client_id.clone(),
        revoked.digest.clone(),
    )
    .expect("authenticate before revocation");
    revoke_self(&mut connection, context).expect("revoke one credential");
    drop(connection);
    Fixture {
        _parent: parent,
        root_path,
        installation_id: identity.installation_id,
        revoked,
        active,
    }
}

fn migrate_open(path: &Path) -> Result<Connection, CoreError> {
    let root = OwnedRoot::open(path, RootPurpose::EngineData).expect("reopen protected root");
    open_database(&root, &CorePolicy::default())
}

fn downgrade_to(fixture: &Fixture, version: i64) {
    assert!(matches!(version, 1 | 2));
    let connection = Connection::open(fixture.root_path.join(DATABASE_NAME))
        .expect("historical fixture database");
    connection
        .execute_batch("DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs; DROP TABLE input_upload_reservations;")
        .expect("remove v3-to-v4 schema difference");
    if version == 1 {
        connection
            .execute_batch("DROP TABLE internal_shutdowns;")
            .expect("remove v1-to-v2 schema difference");
    }
    connection
        .execute_batch("ALTER TABLE credentials DROP COLUMN grant_policy;")
        .expect("remove v2-to-v3 schema difference");
    connection
        .pragma_update(None, "user_version", version)
        .expect("restore historical schema marker");
}

fn expected_grants(grants: &[&str]) -> Vec<String> {
    grants.iter().map(|grant| (*grant).to_owned()).collect()
}

#[test]
fn recovery_backup_keeps_the_required_free_space_floor() {
    let backup_size = 12_345_u64;
    let required = backup_size + RECOVERY_BACKUP_FREE_SPACE_FLOOR_BYTES;
    assert_eq!(require_recovery_backup_space(required, backup_size), Ok(()));
    assert_eq!(
        require_recovery_backup_space(required - 1, backup_size),
        Err(CoreError::StoreUnavailable)
    );
}

fn credential_rows(path: &Path) -> Vec<CredentialRow> {
    let connection = Connection::open(path.join(DATABASE_NAME)).expect("database");
    let mut statement = connection
        .prepare(
            "SELECT client_id,enrollment_id,secret_digest,revoked_at_ms,grant_policy
             FROM credentials ORDER BY client_id",
        )
        .expect("credential query");
    statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("credential rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("credential values")
}

#[test]
fn schema_v1_and_v2_migrate_to_v5_without_changing_identity_or_credentials() {
    for version in [1, 2] {
        let fixture = new_fixture();
        downgrade_to(&fixture, version);

        let mut connection = migrate_open(&fixture.root_path).expect("migrate historical schema");
        let identity = read_identity(&connection).expect("migrated identity");
        assert_eq!(identity.installation_id, fixture.installation_id);
        let context = authenticate(
            &mut connection,
            fixture.active.client_id.clone(),
            fixture.active.digest.clone(),
        )
        .expect("existing active credential remains usable");
        assert_eq!(
            context.granted_operations(),
            expected_grants(&INITIAL_GRANTS)
        );
        assert!(matches!(
            authenticate(
                &mut connection,
                fixture.revoked.client_id.clone(),
                fixture.revoked.digest.clone()
            ),
            Err(CoreError::Unauthorized)
        ));
        drop(connection);

        let rows = credential_rows(&fixture.root_path);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, fixture.revoked.client_id.as_str());
        assert_eq!(rows[0].1, fixture.revoked.enrollment_id.as_str());
        assert_eq!(rows[0].2.as_slice(), fixture.revoked.digest.as_bytes());
        assert!(rows[0].3.is_some());
        assert_eq!(rows[0].4, "core-v1");
        assert_eq!(rows[1].0, fixture.active.client_id.as_str());
        assert_eq!(rows[1].1, fixture.active.enrollment_id.as_str());
        assert_eq!(rows[1].2.as_slice(), fixture.active.digest.as_bytes());
        assert_eq!(rows[1].3, None);
        assert_eq!(rows[1].4, "core-v1");
        assert_eq!(
            read_grants_from_path(&fixture.root_path, &fixture.active.client_id),
            expected_grants(&INITIAL_GRANTS)
        );

        let database =
            Connection::open(fixture.root_path.join(DATABASE_NAME)).expect("migrated database");
        let schema_version: i64 = database
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("schema version");
        assert_eq!(schema_version, SCHEMA_VERSION);
        let backup =
            Connection::open(fixture.root_path.join(UPGRADE_BACKUP)).expect("pre-upgrade backup");
        let backup_version: i64 = backup
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("backup schema version");
        assert_eq!(backup_version, version);
        let integrity: String = backup
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("backup integrity");
        assert_eq!(integrity, "ok");
    }
}

fn read_grants_from_path(path: &Path, client_id: &ClientId) -> Vec<String> {
    let connection = Connection::open(path.join(DATABASE_NAME)).expect("database");
    read_grants(&connection, client_id).expect("credential grants")
}

#[test]
fn v2_migration_preserves_legacy_backup_and_refuses_v5_backup_collision() {
    let fixture = new_fixture();
    downgrade_to(&fixture, 2);

    let legacy_bytes = b"pre-existing legacy recovery artifact";
    let legacy_path = fixture.root_path.join(LEGACY_BACKUP);
    let migration_root = OwnedRoot::open(&fixture.root_path, RootPurpose::EngineData)
        .expect("protected fixture root");
    migration_root
        .ensure_private_directory(&dissect3d_platform::RelativePath::parse("recovery").unwrap())
        .expect("private recovery directory");
    migration_root
        .write_atomic(
            &dissect3d_platform::RelativePath::parse(LEGACY_BACKUP).unwrap(),
            legacy_bytes,
        )
        .expect("legacy backup fixture");
    let prior_v3_bytes = b"retained v3 pre-upgrade backup";
    migration_root
        .write_atomic(
            &dissect3d_platform::RelativePath::parse("recovery/metadata-v3-upgrade.sqlite3")
                .unwrap(),
            prior_v3_bytes,
        )
        .expect("prior version-three backup fixture");
    drop(migrate_open(&fixture.root_path).expect("legacy artifact must remain untouched"));
    assert_eq!(
        std::fs::read(&legacy_path).expect("legacy bytes"),
        legacy_bytes
    );
    assert_eq!(
        std::fs::read(
            fixture
                .root_path
                .join("recovery/metadata-v3-upgrade.sqlite3")
        )
        .expect("prior v3 backup bytes"),
        prior_v3_bytes
    );

    let second = new_fixture();
    downgrade_to(&second, 2);
    let v5_path = second.root_path.join(UPGRADE_BACKUP);
    OwnedRoot::open(&second.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .ensure_private_directory(&dissect3d_platform::RelativePath::parse("recovery").unwrap())
        .expect("private recovery directory");
    let v5_bytes = b"existing v5 backup must never be overwritten";
    OwnedRoot::open(&second.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .write_atomic(
            &dissect3d_platform::RelativePath::parse(UPGRADE_BACKUP).unwrap(),
            v5_bytes,
        )
        .expect("private backup fixture");

    assert!(matches!(
        migrate_open(&second.root_path),
        Err(CoreError::StoreIncompatible)
    ));
    assert_eq!(
        std::fs::read(&v5_path).expect("v5 collision bytes"),
        v5_bytes
    );
    let database =
        Connection::open(second.root_path.join(DATABASE_NAME)).expect("original database");
    let version: i64 = database
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("original version");
    assert_eq!(version, 2);
    let policy_column: Option<String> = database
        .query_row(
            "SELECT name FROM pragma_table_info('credentials') WHERE name='grant_policy'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("policy column check");
    assert_eq!(policy_column, None);
}

#[test]
fn backup_sync_failure_aborts_migration_without_mutating_v2_store() {
    let fixture = new_fixture();
    downgrade_to(&fixture, 2);
    let root = OwnedRoot::open(&fixture.root_path, RootPurpose::EngineData)
        .expect("reopen protected root");
    let database_path = fixture.root_path.join(DATABASE_NAME);
    let mut connection = open_internal_database(&database_path).expect("open v2 database");
    let sync_attempted = std::cell::Cell::new(false);

    assert_eq!(
        run_migrations_with_backup_at(
            &mut connection,
            &root,
            &CORE_MIGRATIONS,
            |source, root, path| {
                retain_verified_backup_at_with_sync(source, root, path, |_| {
                    sync_attempted.set(true);
                    Err(CoreError::StoreUnavailable)
                })
            }
        ),
        Err(CoreError::StoreUnavailable)
    );
    assert!(sync_attempted.get());

    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("version after failed sync");
    assert_eq!(version, 2);
    let grant_policy: Option<String> = connection
        .query_row(
            "SELECT name FROM pragma_table_info('credentials') WHERE name='grant_policy'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("grant-policy column after failed sync");
    assert_eq!(grant_policy, None);
    drop(connection);

    let backup = Connection::open(fixture.root_path.join(UPGRADE_BACKUP))
        .expect("verified pre-upgrade backup remains available");
    let backup_version: i64 = backup
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("backup version after failed sync");
    assert_eq!(backup_version, 2);
    let integrity: String = backup
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("backup integrity after failed sync");
    assert_eq!(integrity, "ok");
}

#[test]
fn unknown_newer_schema_is_refused_without_mutating_database_bytes() {
    let fixture = new_fixture();
    let database_path = fixture.root_path.join(DATABASE_NAME);
    let connection = Connection::open(&database_path).expect("database");
    connection
        .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
        .expect("future version marker");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint fixture");
    drop(connection);
    let original = std::fs::read(&database_path).expect("original database bytes");
    assert!(matches!(
        migrate_open(&fixture.root_path),
        Err(CoreError::StoreIncompatible)
    ));
    assert_eq!(
        std::fs::read(database_path).expect("database after refusal"),
        original
    );
    assert!(!fixture.root_path.join(UPGRADE_BACKUP).exists());
}

#[test]
fn core_and_submission_clients_have_independent_exact_policy_grants() {
    let parent = tempdir().expect("temporary engine root");
    let root_path = parent.path().join("metadata-root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let mut connection = open_database(&root, &CorePolicy::default()).expect("store");
    let identity = read_identity(&connection).expect("store identity");
    let owner = current_owner_identity().expect("owner identity");
    let core_client = ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap();
    let core_enrollment = EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap();
    let core_digest = TokenDigest::new(Sha256::digest([0x11; 32]).into());
    let submission_client = ClientId::parse("cli_1123456789abcdef0123456789abcdef").unwrap();
    let submission_enrollment =
        EnrollmentId::parse("enr_1123456789abcdef0123456789abcdef").unwrap();
    let submission_digest = TokenDigest::new(Sha256::digest([0x22; 32]).into());

    let core_receipt = enroll(
        &mut connection,
        VerifiedEnrollment::new(
            owner.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            core_enrollment.clone(),
            core_client.clone(),
            core_digest.clone(),
        ),
    )
    .expect("core enrollment");
    assert_eq!(
        core_receipt.granted_operations,
        expected_grants(&INITIAL_GRANTS)
    );

    let submission_receipt = enroll(
        &mut connection,
        VerifiedEnrollment::new_submission_access(
            owner.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            submission_enrollment.clone(),
            submission_client.clone(),
            submission_digest.clone(),
        ),
    )
    .expect("opt-in enrollment");
    assert_eq!(
        submission_receipt.granted_operations,
        expected_grants(&SUBMISSION_GRANTS)
    );

    let core_context = authenticate(&mut connection, core_client.clone(), core_digest.clone())
        .expect("core authentication");
    let submission_context = authenticate(
        &mut connection,
        submission_client.clone(),
        submission_digest.clone(),
    )
    .expect("submission authentication");
    for operation in ["inputs.create", "jobs.submit", "jobs.list", "jobs.show"] {
        assert!(
            !core_context
                .granted_operations()
                .iter()
                .any(|grant| grant == operation)
        );
        assert!(
            submission_context
                .granted_operations()
                .iter()
                .any(|grant| grant == operation)
        );
    }

    let replay = enroll(
        &mut connection,
        VerifiedEnrollment::new_submission_access(
            owner.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            submission_enrollment.clone(),
            submission_client.clone(),
            submission_digest.clone(),
        ),
    )
    .expect("same-policy enrollment replay");
    assert!(replay.replayed);
    assert_eq!(
        replay.granted_operations,
        expected_grants(&SUBMISSION_GRANTS)
    );
    assert!(matches!(
        enroll(
            &mut connection,
            VerifiedEnrollment::new(
                owner,
                identity.installation_id,
                identity.instance_id,
                submission_enrollment,
                submission_client.clone(),
                submission_digest.clone(),
            )
        ),
        Err(CoreError::Conflict)
    ));

    revoke_self(&mut connection, submission_context).expect("revoke opt-in client");
    assert!(authenticate(&mut connection, core_client, core_digest).is_ok());
    assert!(matches!(
        authenticate(&mut connection, submission_client, submission_digest),
        Err(CoreError::Unauthorized)
    ));
}

#[test]
fn unknown_policy_and_non_exact_grants_fail_closed_on_authentication() {
    let parent = tempdir().expect("temporary engine root");
    let root_path = parent.path().join("metadata-root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let mut connection = open_database(&root, &CorePolicy::default()).expect("store");
    let identity = read_identity(&connection).expect("store identity");
    let client = ClientId::parse("cli_0123456789abcdef0123456789abcdef").unwrap();
    let enrollment = EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").unwrap();
    let token_digest = TokenDigest::new(Sha256::digest([0x33; 32]).into());
    enroll(
        &mut connection,
        VerifiedEnrollment::new(
            current_owner_identity().expect("owner identity"),
            identity.installation_id,
            identity.instance_id,
            enrollment,
            client.clone(),
            token_digest.clone(),
        ),
    )
    .expect("core enrollment");
    connection
        .execute_batch("PRAGMA ignore_check_constraints=ON;")
        .expect("simulate an unrecognized future policy value");
    connection
        .execute(
            "UPDATE credentials SET grant_policy='future-v9' WHERE client_id=?1",
            [client.as_str()],
        )
        .expect("seed unknown policy");
    assert!(matches!(
        authenticate(&mut connection, client.clone(), token_digest.clone()),
        Err(CoreError::InvalidStore)
    ));

    connection
        .execute(
            "UPDATE credentials SET grant_policy='core-v1' WHERE client_id=?1",
            [client.as_str()],
        )
        .expect("restore recognized policy");
    connection
        .execute(
            "INSERT INTO credential_grants(client_id,operation) VALUES(?1,'jobs.submit')",
            [client.as_str()],
        )
        .expect("seed unauthorized grant");
    assert!(matches!(
        authenticate(&mut connection, client, token_digest),
        Err(CoreError::InvalidStore)
    ));
}

#[test]
fn failed_upgrade_second_start_preserves_both_images_until_explicit_archive_and_retry() {
    for sync_failure in [true, false] {
        let fixture = new_fixture();
        downgrade_to(&fixture, 2);
        let root = OwnedRoot::open(&fixture.root_path, RootPurpose::EngineData).unwrap();
        let database_path = fixture.root_path.join(DATABASE_NAME);
        let backup_path = fixture.root_path.join(UPGRADE_BACKUP);
        let mut connection = open_internal_database(&database_path).unwrap();
        configure_connection(&connection).unwrap();
        let failing_steps = [
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
                apply: |_| Err(CoreError::StoreUnavailable),
            },
            MigrationStep {
                from: 5,
                to: 6,
                apply: add_job_tables,
            },
        ];
        let result = if sync_failure {
            run_migrations_with_backup_at(
                &mut connection,
                &root,
                &CORE_MIGRATIONS,
                |source, root, path| {
                    retain_verified_backup_at_with_sync(source, root, path, |_| {
                        Err(CoreError::StoreUnavailable)
                    })
                },
            )
        } else {
            run_migrations(&mut connection, &root, &failing_steps)
        };
        assert_eq!(result, Err(CoreError::StoreUnavailable));
        drop(connection);
        let before = std::fs::read(&database_path).unwrap();
        let backup_before = std::fs::read(&backup_path).unwrap();
        assert!(matches!(
            migrate_open(&fixture.root_path),
            Err(CoreError::StoreIncompatible)
        ));
        assert_eq!(std::fs::read(&database_path).unwrap(), before);
        assert_eq!(std::fs::read(&backup_path).unwrap(), backup_before);

        // Operator inspection: only the original metadata DB is authoritative.
        for path in [&database_path, &backup_path] {
            let inspected =
                Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            let integrity: String = inspected
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .unwrap();
            assert_eq!(integrity, "ok");
            let version: i64 = inspected
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, 2);
            assert_eq!(
                read_identity(&inspected).unwrap().installation_id,
                fixture.installation_id
            );
        }
        // Explicit offline archival, never restore or edit the authoritative DB.
        // create_new preserves any prior archive; source is removed only after a synced, verified copy.
        let archive_path = fixture
            .root_path
            .join("recovery/metadata-v5-failed-attempt.sqlite3");
        let mut archive = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&archive_path)
            .unwrap();
        std::io::copy(
            &mut std::fs::File::open(&backup_path).unwrap(),
            &mut archive,
        )
        .unwrap();
        archive.sync_all().unwrap();
        drop(archive);
        assert_eq!(std::fs::read(&archive_path).unwrap(), backup_before);
        std::fs::remove_file(&backup_path).unwrap();
        let mut recovered =
            migrate_open(&fixture.root_path).expect("retry additive migration from original");
        assert_eq!(
            read_identity(&recovered).unwrap().installation_id,
            fixture.installation_id
        );
        assert!(
            authenticate(
                &mut recovered,
                fixture.active.client_id.clone(),
                fixture.active.digest.clone()
            )
            .is_ok()
        );
        assert!(matches!(
            authenticate(
                &mut recovered,
                fixture.revoked.client_id.clone(),
                fixture.revoked.digest.clone()
            ),
            Err(CoreError::Unauthorized)
        ));
        assert_eq!(std::fs::read(&archive_path).unwrap(), backup_before);
        let version: i64 = recovered
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
