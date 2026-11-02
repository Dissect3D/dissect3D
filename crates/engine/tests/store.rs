use dissect3d_api::{ClientId, EnrollmentId, TokenDigest};
use dissect3d_engine::{CoreError, CorePolicy, Store, VerifiedEnrollment};
use dissect3d_platform::{AuthorityLease, OwnedRoot, RootPurpose, current_owner_identity};
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
fn installation_identity_survives_reopen_and_session_identity_changes() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("engine store");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("lease");
    let first = Store::open(root, lease, &CorePolicy::default()).expect("first store");
    let first_identity = first.identity().expect("first identity");
    drop(first);

    let root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("reopen root");
    let lease = AuthorityLease::acquire(&root).expect("reacquire lease");
    let second = Store::open(root, lease, &CorePolicy::default()).expect("reopen store");
    let second_identity = second.identity().expect("second identity");
    assert_eq!(
        first_identity.installation_id,
        second_identity.installation_id
    );
    assert_ne!(first_identity.instance_id, second_identity.instance_id);
}

#[test]
fn unknown_store_version_is_refused_without_mutating_file_bytes() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("future store");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let database_path = root_path.join("metadata.sqlite3");
    let connection = Connection::open(&database_path).expect("fixture connection");
    connection
        .pragma_update(None, "application_id", 0x4433_4431_i64)
        .expect("application marker");
    connection
        .pragma_update(None, "user_version", 99_i64)
        .expect("future version");
    drop(connection);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&database_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect fixture");
    }
    let original = std::fs::read(&database_path).expect("original database bytes");
    let lease = AuthorityLease::acquire(&root).expect("lease");

    assert!(matches!(
        Store::open(root, lease, &CorePolicy::default()),
        Err(CoreError::StoreIncompatible)
    ));
    assert_eq!(
        std::fs::read(database_path).expect("database after refusal"),
        original
    );
}

#[cfg(unix)]
#[test]
fn database_symlink_is_refused_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("symlinked database root");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let target = parent.path().join("outside.sqlite3");
    let original = b"caller-owned bytes";
    std::fs::write(&target, original).expect("outside target");
    symlink(&target, root_path.join("metadata.sqlite3")).expect("database symlink");
    let lease = AuthorityLease::acquire(&root).expect("authority");

    assert!(matches!(
        Store::open(root, lease, &CorePolicy::default()),
        Err(CoreError::Platform(_))
    ));
    assert_eq!(
        std::fs::read(target).expect("target after refusal"),
        original
    );
}

#[cfg(unix)]
#[test]
fn database_hard_link_is_refused_without_touching_its_target() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("hard-linked database root");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let target = parent.path().join("outside.sqlite3");
    let original = b"caller-owned bytes";
    std::fs::write(&target, original).expect("outside target");
    std::fs::hard_link(&target, root_path.join("metadata.sqlite3")).expect("database hard link");
    let lease = AuthorityLease::acquire(&root).expect("authority");

    assert!(matches!(
        Store::open(root, lease, &CorePolicy::default()),
        Err(CoreError::Platform(_))
    ));
    assert_eq!(
        std::fs::read(target).expect("target after refusal"),
        original
    );
}

#[test]
fn enrollment_replays_exactly_and_revocation_survives_reauthentication() {
    let parent = TempDir::new().expect("temporary parent");
    let root_path = parent.path().join("credential store");
    let root =
        OwnedRoot::create_private(&root_path, RootPurpose::EngineData).expect("private root");
    let lease = AuthorityLease::acquire(&root).expect("authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("open store");
    let identity = store.identity().expect("store identity");
    let owner = current_owner_identity().expect("owner identity");
    let enrollment = VerifiedEnrollment::new(
        owner.clone(),
        identity.installation_id.clone(),
        identity.instance_id.clone(),
        EnrollmentId::parse("enr_0123456789abcdef0123456789abcdef").expect("enrollment id"),
        ClientId::parse("cli_0123456789abcdef0123456789abcdef").expect("client id"),
        TokenDigest::new([42; 32]),
    );
    let receipt = store.enroll(enrollment).expect("durable enrollment");
    assert!(!receipt.replayed);
    let replay = store
        .enroll(VerifiedEnrollment::new(
            owner.clone(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            receipt.enrollment_id.clone(),
            receipt.client_id.clone(),
            TokenDigest::new([42; 32]),
        ))
        .expect("exact replay");
    assert!(replay.replayed);
    assert_eq!(receipt.created_at_ms, replay.created_at_ms);
    assert_eq!(receipt.granted_operations, replay.granted_operations);
    let changed_digest = VerifiedEnrollment::new(
        owner.clone(),
        identity.installation_id.clone(),
        identity.instance_id.clone(),
        receipt.enrollment_id.clone(),
        receipt.client_id.clone(),
        TokenDigest::new([43; 32]),
    );
    assert!(matches!(
        store.enroll(changed_digest),
        Err(CoreError::Conflict)
    ));
    drop(store);

    let root = OwnedRoot::open(&root_path, RootPurpose::EngineData).expect("reopen root");
    let lease = AuthorityLease::acquire(&root).expect("reacquire authority");
    let store = Store::open(root, lease, &CorePolicy::default()).expect("reopen store");
    let context = store
        .authenticate(receipt.client_id.clone(), TokenDigest::new([42; 32]))
        .expect("credential authentication");
    let stale_context = context.clone();
    let revoked = store.revoke_self(context).expect("durable own revocation");
    assert!(revoked.revoked);
    assert!(matches!(
        store.authenticate(receipt.client_id.clone(), TokenDigest::new([42; 32])),
        Err(CoreError::Unauthorized)
    ));
    assert_eq!(
        store.revoke_self(stale_context),
        Err(CoreError::Unauthorized)
    );
    let current_identity = store.identity().expect("current instance identity");
    assert!(matches!(
        store.enroll(VerifiedEnrollment::new(
            owner,
            current_identity.installation_id,
            current_identity.instance_id,
            receipt.enrollment_id,
            receipt.client_id,
            TokenDigest::new([42; 32]),
        )),
        Err(CoreError::Unauthorized)
    ));
}
