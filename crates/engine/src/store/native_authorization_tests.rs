#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::*;
fn database() -> Connection {
    let mut db = Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    initialize_schema(&mut db).unwrap();
    db
}
fn enrollment(db: &Connection, policy: GrantPolicy) -> VerifiedEnrollment {
    let id = read_identity(db).unwrap();
    VerifiedEnrollment {
        owner: current_owner_identity().unwrap(),
        installation_id: id.installation_id,
        instance_id: id.instance_id,
        enrollment_id: dissect3d_api::EnrollmentId::parse("enr_11111111111111111111111111111111")
            .unwrap(),
        client_id: ClientId::parse("cli_11111111111111111111111111111111").unwrap(),
        token_digest: TokenDigest::new([1; 32]),
        grant_policy: policy,
    }
}
#[cfg(unix)]
#[test]
fn execution_enrollment_rolls_back_credentials_and_grants_when_authorization_cannot_commit() {
    let mut db = database();
    let request = enrollment(&db, GrantPolicy::ExecutionV1);
    db.execute_batch("CREATE TRIGGER reject_authority BEFORE INSERT ON client_authorizations BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(matches!(
        enroll(&mut db, request),
        Err(CoreError::StoreUnavailable)
    ));
    for table in ["credentials", "credential_grants", "client_authorizations"] {
        assert_eq!(
            db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    db.execute_batch("DROP TRIGGER reject_authority;").unwrap();
    let request = enrollment(&db, GrantPolicy::ExecutionV1);
    let first = enroll(&mut db, request).unwrap();
    assert_eq!(first.granted_operations.len(), 15);
    let request = enrollment(&db, GrantPolicy::ExecutionV1);
    assert!(enroll(&mut db, request).unwrap().replayed);
    assert_eq!(
        db.query_row("SELECT count(*) FROM credential_grants", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        9
    );
    assert_eq!(
        db.query_row(
            "SELECT authorization_id FROM client_authorizations",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "enr_11111111111111111111111111111111"
    );
}
#[test]
fn legacy_enrollment_replay_is_stable_and_corrupt_authorization_policy_fails_closed() {
    let mut db = database();
    let request = enrollment(&db, GrantPolicy::CoreV1);
    let original = enroll(&mut db, request).unwrap();
    let identity = read_identity(&db).unwrap();
    let client = original.client_id.clone();
    reauthorization::authorize(
        &mut db,
        reauthorization::VerifiedAuthorization {
            owner: current_owner_identity().unwrap(),
            installation_id: identity.installation_id,
            instance_id: identity.instance_id,
            client_id: client.clone(),
            token_digest: TokenDigest::new([1; 32]),
            authorization_id: "aut_22222222222222222222222222222222".into(),
        },
    )
    .unwrap();
    let request = enrollment(&db, GrantPolicy::CoreV1);
    assert_eq!(
        enroll(&mut db, request).unwrap().granted_operations,
        original.granted_operations
    );
    assert_eq!(
        authenticate(&mut db, client.clone(), TokenDigest::new([1; 32]))
            .unwrap()
            .granted_operations
            .len(),
        15
    );
    db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE client_authorizations SET grant_policy='future-v9';").unwrap();
    assert!(matches!(
        authenticate(&mut db, client, TokenDigest::new([1; 32])),
        Err(CoreError::InvalidStore)
    ));
    let request = enrollment(&db, GrantPolicy::CoreV1);
    assert!(matches!(
        enroll(&mut db, request),
        Err(CoreError::InvalidStore)
    ));
}
