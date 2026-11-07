//! Additional schema-six regressions; historical migration assertions stay intact.
use super::*;

#[test]
fn v5_upgrade_preserves_prior_backup_and_creates_distinct_v6_image() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("engine");
    let root =
        OwnedRoot::create_private(&path, dissect3d_platform::RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    let identity = store.identity().unwrap();
    drop(store);
    let db = Connection::open(path.join(DATABASE_NAME)).unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE job_acceptance_events; DROP TABLE job_inputs; DROP TABLE submission_bindings; DROP TABLE jobs; DROP TABLE job_sequence; PRAGMA user_version=5;").unwrap();
    drop(db);
    let root = OwnedRoot::open(&path, dissect3d_platform::RootPurpose::EngineData).unwrap();
    let prior = RelativePath::parse("recovery/metadata-v5-upgrade.sqlite3").unwrap();
    root.write_atomic(&prior, b"immutable earlier upgrade image")
        .unwrap();
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    assert_eq!(
        store.identity().unwrap().installation_id,
        identity.installation_id
    );
    drop(store);
    assert_eq!(
        std::fs::read(path.join(prior.as_str())).unwrap(),
        b"immutable earlier upgrade image"
    );
    let backup = Connection::open_with_flags(
        path.join("recovery/metadata-v6-upgrade.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        backup
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
}
