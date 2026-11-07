use dissect3d_api::{ClientId, EnrollmentId, TokenDigest};
use dissect3d_engine::{CoreError, CorePolicy, Store, VerifiedEnrollment};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RootPurpose, current_owner_identity};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tempfile::TempDir;

const CORE_GRANTS: [&str; 5] = [
    "auth.revoke_self",
    "auth.status",
    "engine.info",
    "engine.shutdown",
    "operation.show_own",
];
const UPGRADE_BACKUP: &str = "recovery/metadata-v6-upgrade.sqlite3";
const LEGACY_BACKUP: &str = "recovery/metadata-upgrade.sqlite3";

struct CredentialSeed {
    client_id: ClientId,
    enrollment_id: EnrollmentId,
    digest: TokenDigest,
}

struct Fixture {
    _parent: TempDir,
    root_path: PathBuf,
    installation_id: dissect3d_api::InstallationId,
    revoked: CredentialSeed,
    active: CredentialSeed,
}

fn seed(client: &str, enrollment: &str, byte: u8) -> CredentialSeed {
    CredentialSeed {
        client_id: ClientId::parse(client).expect("client id"),
        enrollment_id: EnrollmentId::parse(enrollment).expect("enrollment id"),
        digest: TokenDigest::new(Sha256::digest([byte; 32]).into()),
    }
}

fn fixture() -> Fixture {
    let parent = tempfile::tempdir().expect("temporary parent");
    let root_path = parent.path().join("engine-root");
    let root = OwnedRoot::create_private(&root_path, RootPurpose::EngineData)
        .expect("private engine root");
    let lease = AuthorityLease::acquire(&root).expect("authority lease");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("initial store");
    let identity = store.identity().expect("initial identity");
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
        store
            .enroll(VerifiedEnrollment::new(
                owner.clone(),
                identity.installation_id.clone(),
                identity.instance_id.clone(),
                credential.enrollment_id.clone(),
                credential.client_id.clone(),
                credential.digest.clone(),
            ))
            .expect("core-only enrollment");
    }
    let context = store
        .authenticate(revoked.client_id.clone(), revoked.digest.clone())
        .expect("authenticate before revocation");
    store.revoke_self(context).expect("revoke first client");
    drop(store);
    Fixture {
        _parent: parent,
        root_path,
        installation_id: identity.installation_id,
        revoked,
        active,
    }
}

fn downgrade_to(fixture: &Fixture, version: i64) {
    assert!(matches!(version, 1 | 2));
    let connection = Connection::open(fixture.root_path.join("metadata.sqlite3"))
        .expect("historical fixture database");
    if version == 1 {
        connection
            .execute_batch("DROP TABLE internal_shutdowns;")
            .expect("remove v1-to-v2 schema difference");
    }
    connection
        .execute_batch("ALTER TABLE credentials DROP COLUMN grant_policy;")
        .expect("remove v2-to-v3 schema difference");
    connection
        .execute_batch("DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE job_acceptance_events; DROP TABLE jobs; DROP TABLE job_sequence; DROP TABLE engine_clock; DROP TABLE captured_inputs; DROP TABLE input_upload_reservations;")
        .expect("remove v3-to-v4 schema difference");
    connection
        .pragma_update(None, "user_version", version)
        .expect("historical version marker");
}

fn reopen(fixture: &Fixture) -> Result<Store, CoreError> {
    let root = OwnedRoot::open(&fixture.root_path, RootPurpose::EngineData)
        .expect("reopen protected root");
    let lease = AuthorityLease::acquire(&root).expect("reacquire authority");
    Store::open(root, lease, &CorePolicy::default())
}

fn assert_preserved_credentials(fixture: &Fixture) {
    let connection =
        Connection::open(fixture.root_path.join("metadata.sqlite3")).expect("migrated database");
    let mut statement = connection
        .prepare(
            "SELECT client_id,enrollment_id,secret_digest,revoked_at_ms,grant_policy
             FROM credentials ORDER BY client_id",
        )
        .expect("credential query");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .expect("credential rows")
        .collect::<Result<Vec<_>, _>>()
        .expect("credential values");
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
}

#[test]
fn v1_and_v2_upgrade_preserves_identity_grants_digests_and_revocation() {
    for version in [1, 2] {
        let fixture = fixture();
        downgrade_to(&fixture, version);
        let store = reopen(&fixture).expect("historical schema migrates");
        let identity = store.identity().expect("migrated identity");
        assert_eq!(identity.installation_id, fixture.installation_id);
        let context = store
            .authenticate(
                fixture.active.client_id.clone(),
                fixture.active.digest.clone(),
            )
            .expect("active core credential remains usable");
        assert_eq!(
            context
                .granted_operations()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            CORE_GRANTS
        );
        assert!(matches!(
            store.authenticate(
                fixture.revoked.client_id.clone(),
                fixture.revoked.digest.clone()
            ),
            Err(CoreError::Unauthorized)
        ));
        drop(store);
        assert_preserved_credentials(&fixture);

        let backup = Connection::open(fixture.root_path.join(UPGRADE_BACKUP))
            .expect("pre-upgrade SQLite backup");
        let backup_version: i64 = backup
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("backup source version");
        assert_eq!(backup_version, version);
        let integrity: String = backup
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("backup integrity");
        assert_eq!(integrity, "ok");
    }
}

#[test]
fn v2_upgrade_preserves_legacy_backup_and_refuses_v5_backup_collision() {
    let legacy_fixture = fixture();
    downgrade_to(&legacy_fixture, 2);
    let legacy_path = legacy_fixture.root_path.join(LEGACY_BACKUP);
    OwnedRoot::open(&legacy_fixture.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .ensure_private_directory(&dissect3d_platform::RelativePath::parse("recovery").unwrap())
        .expect("private recovery directory");
    let legacy_bytes = b"existing legacy backup";
    OwnedRoot::open(&legacy_fixture.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .write_atomic(
            &dissect3d_platform::RelativePath::parse(LEGACY_BACKUP).unwrap(),
            legacy_bytes,
        )
        .expect("private backup fixture");
    drop(reopen(&legacy_fixture).expect("legacy backup remains untouched"));
    assert_eq!(
        std::fs::read(&legacy_path).expect("legacy backup"),
        legacy_bytes
    );

    let second = fixture();
    downgrade_to(&second, 2);
    let upgrade_path = second.root_path.join(UPGRADE_BACKUP);
    OwnedRoot::open(&second.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .ensure_private_directory(&dissect3d_platform::RelativePath::parse("recovery").unwrap())
        .expect("private recovery directory");
    let upgrade_bytes = b"existing v5 backup";
    OwnedRoot::open(&second.root_path, RootPurpose::EngineData)
        .expect("protected fixture root")
        .write_atomic(
            &dissect3d_platform::RelativePath::parse(UPGRADE_BACKUP).unwrap(),
            upgrade_bytes,
        )
        .expect("private backup fixture");
    assert!(matches!(reopen(&second), Err(CoreError::StoreIncompatible)));
    assert_eq!(
        std::fs::read(&upgrade_path).expect("existing v5 backup"),
        upgrade_bytes
    );

    let database = Connection::open(second.root_path.join("metadata.sqlite3"))
        .expect("database after refused migration");
    let version: i64 = database
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("original schema version");
    assert_eq!(version, 2);
    let policy_column: Option<String> = database
        .query_row(
            "SELECT name FROM pragma_table_info('credentials') WHERE name='grant_policy'",
            [],
            |row| row.get(0),
        )
        .optional()
        .expect("policy column query");
    assert_eq!(policy_column, None);
}
