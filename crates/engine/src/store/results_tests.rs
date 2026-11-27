//! RP-P02/1, /5, /6 Store regressions on real SQLite (every OS).
#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::super::results_schema::DROP_V8_TABLES;
use super::*;
use crate::domain::publication_policy::{
    PRIVATE_BYTES_MAX, RECLAIM_ENTRIES_PER_TURN, RESULT_RECORDS_MAX, STORAGE_FREE_RESERVE_BYTES,
};
use dissect3d_platform::RootPurpose;

const PLENTY: u64 = u64::MAX / 4;

pub(crate) fn store_at(path: &Path) -> Connection {
    let mut db = Connection::open(path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    initialize_schema(&mut db).unwrap();
    db
}

fn hex32(n: u32) -> String {
    format!("{n:032x}")
}

/// A credential, a job and its running attempt with the given identities.
pub(crate) fn seed_running(db: &Connection, job: &str, attempt: &str, sequence: i64) {
    db.execute(
        "INSERT OR IGNORE INTO credentials(client_id,enrollment_id,secret_digest,client_kind,created_at_ms)
         VALUES('cli_11111111111111111111111111111111','enr_11111111111111111111111111111111',zeroblob(32),'cli',1)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO jobs VALUES(?1,'cli_11111111111111111111111111111111',?2,1,'{}','verified')",
        rusqlite::params![job, sequence],
    )
    .unwrap();
    db.execute(
        "INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms)
         VALUES(?1,2,'running','running','pending',1)",
        [job],
    )
    .unwrap();
    db.execute(
        "INSERT INTO job_attempts VALUES(?1,?2,
            (SELECT instance_id FROM service_sessions WHERE termination='active'),
            'ses_'||substr(?1,5),'grt_'||substr(?1,5),1,NULL,'pending')",
        [attempt, job],
    )
    .unwrap();
}

fn running(db: &Connection, n: u32) -> (String, String) {
    let job = format!("job_{}", hex32(n));
    let attempt = format!("att_{}", hex32(n));
    seed_running(db, &job, &attempt, i64::from(n));
    (job, attempt)
}

fn file(name: String, role: FileRole, filename: &str, length: u64) -> ReservedFile {
    ReservedFile {
        object_name: name,
        role,
        filename: filename.to_owned(),
        media_type: "application/octet-stream".to_owned(),
        byte_length: length,
        sha256: [7; 32],
    }
}

fn request(
    n: u32,
    job: &str,
    attempt: &str,
    artifact: u64,
    manifest: u64,
) -> PublicationReservation {
    PublicationReservation {
        result_id: format!("res_{}", hex32(n)),
        publication_id: format!("pub_{}", hex32(n)),
        job_id: job.to_owned(),
        attempt_id: attempt.to_owned(),
        files: vec![
            file(
                format!("art_{}", hex32(n)),
                FileRole::Artifact,
                "mesh.obj",
                artifact,
            ),
            file(
                format!("pub_{}", hex32(n)),
                FileRole::Manifest,
                "manifest.json",
                manifest,
            ),
        ],
        available_space_bytes: PLENTY,
    }
}

fn set_job_state(db: &Connection, job: &str, state: &str) {
    db.execute(
        "UPDATE job_execution SET state=?2 WHERE job_id=?1",
        [job, state],
    )
    .unwrap();
}

fn state(db: &Connection, result_id: &str) -> Option<String> {
    db.query_row(
        "SELECT state FROM publication_allocations WHERE result_id=?1",
        [result_id],
        |r| r.get(0),
    )
    .ok()
}

/// Every row an accepted v7 store owns, for before/after comparison.
fn legacy_dump(db: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    for table in [
        "engine_identity",
        "credentials",
        "credential_grants",
        "captured_inputs",
        "jobs",
        "job_inputs",
        "submission_bindings",
        "job_execution",
        "job_attempts",
        "resource_reservations",
        "job_events",
        "job_sequence",
    ] {
        let mut statement = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let columns = statement.column_count();
        let rows = statement
            .query_map([], |row| {
                let mut values = Vec::new();
                for i in 0..columns {
                    values.push(format!("{:?}", row.get_ref(i)?));
                }
                Ok(values.join("|"))
            })
            .unwrap();
        for row in rows {
            out.push(format!("{table}:{}", row.unwrap()));
        }
    }
    out
}

fn v8_schema(db: &Connection) -> Vec<(String, String)> {
    let mut statement = db
        .prepare(
            "SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND tbl_name IN
             ('publication_allocations','result_files','results','publication_sequence')
             ORDER BY name",
        )
        .unwrap();
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

struct V7Store {
    _parent: tempfile::TempDir,
    path: PathBuf,
    root: OwnedRoot,
    db: Connection,
}

/// A real root holding a v7-shaped store with accepted rows and one external
/// captured-input file.
fn v7_store() -> V7Store {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("engine");
    let root = OwnedRoot::create_private(&path, RootPurpose::EngineData).unwrap();
    let db = open_database(&root, &CorePolicy::default()).unwrap();
    db.execute_batch(DROP_V8_TABLES).unwrap();
    db.pragma_update(None, "user_version", 7).unwrap();
    running(&db, 1);
    db.execute_batch(
        "INSERT INTO captured_inputs VALUES('inp_11111111111111111111111111111111','cli_11111111111111111111111111111111','application/octet-stream',7,zeroblob(32),1,999999,'complete');
         INSERT INTO job_inputs VALUES('job_00000000000000000000000000000001','inp_11111111111111111111111111111111');
         INSERT INTO resource_reservations VALUES('att_00000000000000000000000000000001','cpu:controlled',0);
         UPDATE job_sequence SET value=1;",
    )
    .unwrap();
    root.write_atomic(
        &RelativePath::parse("inputs/data/inp_11111111111111111111111111111111.bin").unwrap(),
        b"v 0 0 0",
    )
    .unwrap();
    V7Store {
        _parent: parent,
        path,
        root,
        db,
    }
}

#[test]
fn fresh_store_is_v8_with_the_same_feature_ddl_as_the_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = store_at(&dir.path().join("fresh.sqlite3"));
    assert_eq!(
        fresh
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8
    );
    let mut old = v7_store();
    let before = legacy_dump(&old.db);
    let earlier = RelativePath::parse("recovery/metadata-v7-upgrade.sqlite3").unwrap();
    old.root.write_atomic(&earlier, b"earlier image").unwrap();
    run_migrations(&mut old.db, &old.root, &CORE_MIGRATIONS).unwrap();
    assert_eq!(
        old.db
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8
    );
    assert_eq!(v8_schema(&old.db), v8_schema(&fresh));
    assert_eq!(v8_schema(&fresh).len(), 6, "4 tables + 2 explicit indexes");
    assert_eq!(legacy_dump(&old.db), before, "accepted rows unchanged");
    assert_eq!(
        old.db
            .query_row("SELECT value FROM publication_sequence", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    // A dedicated v8 image; the earlier one is never replaced.
    assert_eq!(
        std::fs::read(old.path.join(earlier.as_str())).unwrap(),
        b"earlier image"
    );
    assert_eq!(
        recovery_backup_for_version(8).unwrap().as_str(),
        "recovery/metadata-v8-upgrade.sqlite3"
    );
    let backup = Connection::open_with_flags(
        old.path.join("recovery/metadata-v8-upgrade.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(
        backup
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(legacy_dump(&backup), before);
}

#[test]
fn a_failed_v8_upgrade_rolls_back_and_keeps_rows_backup_and_external_files() {
    let mut old = v7_store();
    let before = legacy_dump(&old.db);
    let failing = [MigrationStep {
        from: 7,
        to: 8,
        // Fails after every v8 statement ran inside the upgrade transaction.
        apply: |tx| {
            add_result_tables(tx)?;
            Err(CoreError::StoreUnavailable)
        },
    }];
    assert_eq!(
        run_migrations(&mut old.db, &old.root, &failing),
        Err(CoreError::StoreUnavailable)
    );
    assert_eq!(
        old.db
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert!(v8_schema(&old.db).is_empty());
    assert_eq!(legacy_dump(&old.db), before);
    assert_eq!(
        std::fs::read(
            old.path
                .join("inputs/data/inp_11111111111111111111111111111111.bin")
        )
        .unwrap(),
        b"v 0 0 0"
    );
    let backup = Connection::open_with_flags(
        old.path.join("recovery/metadata-v8-upgrade.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(legacy_dump(&backup), before);
    // The retained image blocks an unattended retry, as for earlier versions.
    assert_eq!(
        run_migrations(&mut old.db, &old.root, &CORE_MIGRATIONS),
        Err(CoreError::StoreIncompatible)
    );
}

#[test]
fn a_reservation_charges_exact_bytes_only_for_the_running_attempt_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    reserve(&mut db, &request(1, &job, &attempt, 100, 20)).unwrap();
    assert_eq!(
        usage(&mut db).unwrap(),
        ResultUsage {
            private_bytes: 120,
            published_bytes: 0,
            unwritten_bytes: 120,
            records: 1
        }
    );
    // A second allocation for the same attempt.
    assert_eq!(
        reserve(&mut db, &request(2, &job, &attempt, 100, 20)),
        Err(CoreError::Conflict)
    );
    // Mismatched job/attempt pair.
    let (other_job, _) = running(&db, 3);
    assert_eq!(
        reserve(&mut db, &request(4, &other_job, &attempt, 1, 1)),
        Err(CoreError::Conflict)
    );
    // Cancel or any end committed first: never allocate.
    for end in ["cancel_requested", "canceled", "interrupted", "failed"] {
        let (job, attempt) = running(&db, 10 + end.len() as u32);
        set_job_state(&db, &job, end);
        assert_eq!(
            reserve(&mut db, &request(20, &job, &attempt, 1, 1)),
            Err(CoreError::Conflict),
            "{end}"
        );
    }
    assert_eq!(
        usage(&mut db).unwrap().records,
        1,
        "refusals record nothing"
    );
}

#[test]
fn malformed_or_colliding_reservations_record_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let mut cases = Vec::new();
    let mut alias = request(1, &job, &attempt, 10, 10);
    alias.files.push(file(
        format!("art_{}", hex32(9)),
        FileRole::Artifact,
        "MESH.OBJ",
        1,
    ));
    cases.push(alias);
    let mut manifest_name = request(1, &job, &attempt, 10, 10);
    manifest_name.files[0].filename = "Manifest.JSON".into();
    cases.push(manifest_name);
    let mut two_manifests = request(1, &job, &attempt, 10, 10);
    two_manifests.files.push(file(
        format!("pub_{}", hex32(9)),
        FileRole::Manifest,
        "m2.json",
        1,
    ));
    cases.push(two_manifests);
    let mut wrong_manifest_object = request(1, &job, &attempt, 10, 10);
    wrong_manifest_object.files[1].object_name = format!("pub_{}", hex32(9));
    cases.push(wrong_manifest_object);
    let mut traversal_object = request(1, &job, &attempt, 10, 10);
    traversal_object.files[0].object_name = "art_../../../../../../../../../../x".into();
    cases.push(traversal_object);
    cases.push(request(1, &job, &attempt, 1_048_577, 10));
    cases.push(request(1, &job, &attempt, 10, 262_145));
    cases.push(request(1, &job, &attempt, 0, 10));
    let mut bad_id = request(1, &job, &attempt, 10, 10);
    bad_id.result_id = "res_XYZ".into();
    cases.push(bad_id);
    for case in cases {
        assert_eq!(
            reserve(&mut db, &case),
            Err(CoreError::Conflict),
            "{case:?}"
        );
    }
    assert_eq!(usage(&mut db).unwrap(), ResultUsage::default());
    assert_eq!(
        db.query_row("SELECT count(*) FROM result_files", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn private_published_record_and_free_space_limits_refuse_before_recording() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let (other_job, other_attempt) = running(&db, 2);
    // Private: an orphan charge is counted until durably reclaimed.
    reserve(
        &mut db,
        &request(2, &other_job, &other_attempt, 1_000, 1_000),
    )
    .unwrap();
    db.execute(
        "UPDATE publication_allocations SET reserved_bytes=?1",
        [(PRIVATE_BYTES_MAX - 100) as i64],
    )
    .unwrap();
    assert_eq!(
        reserve(&mut db, &request(1, &job, &attempt, 90, 11)),
        Err(CoreError::CapacityExceeded("result_private_bytes_max"))
    );
    reserve(&mut db, &request(1, &job, &attempt, 90, 10)).unwrap();
    db.execute("DELETE FROM result_files", []).unwrap();
    db.execute("DELETE FROM publication_allocations", [])
        .unwrap();

    // Free space: exact boundary passes, one byte less refuses. Unwritten
    // preparations and input upload reservations count as promised bytes.
    reserve(&mut db, &request(2, &other_job, &other_attempt, 50, 50)).unwrap();
    db.execute(
        "INSERT INTO input_upload_reservations VALUES('upr_1','inp_22222222222222222222222222222222','cli_11111111111111111111111111111111',400,'application/octet-stream',1)",
        [],
    )
    .unwrap();
    let required = 100 + 400 + 120 + STORAGE_FREE_RESERVE_BYTES;
    let mut low = request(1, &job, &attempt, 100, 20);
    low.available_space_bytes = required - 1;
    assert_eq!(
        reserve(&mut db, &low),
        Err(CoreError::CapacityExceeded("storage_free_reserve_bytes"))
    );
    low.available_space_bytes = required;
    reserve(&mut db, &low).unwrap();
    db.execute("DELETE FROM input_upload_reservations", [])
        .unwrap();
    db.execute("DELETE FROM result_files", []).unwrap();
    db.execute("DELETE FROM publication_allocations", [])
        .unwrap();

    // Published: committed bytes plus every private charge.
    db.execute_batch("PRAGMA foreign_keys=OFF;").unwrap();
    db.execute(
        "INSERT INTO publication_allocations VALUES('res_ffffffffffffffffffffffffffffffff','pub_ffffffffffffffffffffffffffffffff','job_x','att_x','ins_x','published',1,1,1)",
        [],
    )
    .unwrap();
    for i in 0..256_u32 {
        db.execute(
            "INSERT INTO result_files VALUES(?1,'res_ffffffffffffffffffffffffffffffff','artifact',?2,'application/octet-stream',67108864,zeroblob(32))",
            rusqlite::params![format!("art_{}", hex32(1_000 + i)), format!("f{i}.obj")],
        )
        .unwrap();
    }
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    assert_eq!(usage(&mut db).unwrap().published_bytes, 17_179_869_184);
    assert_eq!(
        reserve(&mut db, &request(1, &job, &attempt, 1, 1)),
        Err(CoreError::CapacityExceeded("result_published_bytes_max"))
    );
    db.execute(
        "DELETE FROM result_files WHERE object_name=?1",
        [format!("art_{}", hex32(1_000))],
    )
    .unwrap();
    reserve(&mut db, &request(1, &job, &attempt, 1, 1)).unwrap();

    // Records: allocations of every state.
    let existing = usage(&mut db).unwrap().records;
    db.execute_batch("PRAGMA foreign_keys=OFF; BEGIN;").unwrap();
    for i in existing..RESULT_RECORDS_MAX {
        let id = hex32(100_000 + i as u32);
        db.execute(
            "INSERT INTO publication_allocations VALUES(?1,?2,'job_x',?3,'ins_x','published',1,1,1)",
            rusqlite::params![
                format!("res_{id}"),
                format!("pub_{id}"),
                format!("att_{id}")
            ],
        )
        .unwrap();
    }
    db.execute_batch("COMMIT; PRAGMA foreign_keys=ON;").unwrap();
    let (job3, attempt3) = running(&db, 3);
    let before = usage(&mut db).unwrap();
    assert_eq!(before.records, RESULT_RECORDS_MAX);
    assert_eq!(
        reserve(&mut db, &request(3, &job3, &attempt3, 1, 1)),
        Err(CoreError::CapacityExceeded("result_records_max"))
    );
    assert_eq!(usage(&mut db).unwrap(), before);
}

#[test]
fn only_terminal_unpublished_allocations_are_reclaimed_and_charge_follows_deletion() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let ids = request(1, &job, &attempt, 100, 20);
    reserve(&mut db, &ids).unwrap();
    mark_prepared(&mut db, &ids.result_id).unwrap();
    assert_eq!(
        mark_prepared(&mut db, &ids.result_id),
        Err(CoreError::Conflict)
    );
    // Still running (a slow or lost caller): never reclaimed.
    assert_eq!(claim_reclaim(&mut db).unwrap(), ReclaimBatch::default());
    // A published allocation is never reclaimed even when its job ended.
    let (pub_job, pub_attempt) = running(&db, 2);
    let published = request(2, &pub_job, &pub_attempt, 5, 5);
    reserve(&mut db, &published).unwrap();
    db.execute(
        "UPDATE publication_allocations SET state='published' WHERE result_id=?1",
        [&published.result_id],
    )
    .unwrap();
    db.execute(
        "INSERT INTO results VALUES(?1,?2,?3,1,'1.0',1)",
        [&published.result_id, &pub_job, &pub_attempt],
    )
    .unwrap();
    set_job_state(&db, &pub_job, "succeeded");
    // Defence in depth: a committed result row protects its allocation even
    // if the allocation's state were never moved to `published`.
    let (row_job, row_attempt) = running(&db, 3);
    let referenced = request(3, &row_job, &row_attempt, 5, 5);
    reserve(&mut db, &referenced).unwrap();
    mark_prepared(&mut db, &referenced.result_id).unwrap();
    db.execute(
        "INSERT INTO results VALUES(?1,?2,?3,2,'1.0',1)",
        [&referenced.result_id, &row_job, &row_attempt],
    )
    .unwrap();
    set_job_state(&db, &row_job, "succeeded");

    set_job_state(&db, &job, "interrupted");
    let batch = claim_reclaim(&mut db).unwrap();
    assert_eq!(
        batch.objects,
        vec![
            ids.files[0].object_name.clone(),
            ids.files[1].object_name.clone()
        ]
    );
    assert_eq!(batch.released_bytes, 0);
    assert_eq!(state(&db, &ids.result_id).as_deref(), Some("reclaiming"));
    // A reclaiming identity can never be prepared (or committed) again.
    assert_eq!(
        mark_prepared(&mut db, &ids.result_id),
        Err(CoreError::Conflict)
    );
    // Confirming a live or unknown name changes nothing.
    assert_eq!(
        confirm_reclaimed(&mut db, &[published.files[0].object_name.clone()]),
        Ok(0)
    );
    // Partial deletion keeps the whole charge.
    assert_eq!(
        confirm_reclaimed(&mut db, &[ids.files[0].object_name.clone()]),
        Ok(0)
    );
    assert_eq!(
        usage(&mut db).unwrap().private_bytes,
        130,
        "plus the referenced 10"
    );
    assert_eq!(
        confirm_reclaimed(&mut db, &[ids.files[1].object_name.clone()]),
        Ok(120)
    );
    assert_eq!(state(&db, &ids.result_id), None);
    assert_eq!(
        state(&db, &referenced.result_id).as_deref(),
        Some("prepared")
    );
    assert_eq!(
        usage(&mut db).unwrap(),
        ResultUsage {
            private_bytes: 10,
            published_bytes: 10,
            unwritten_bytes: 0,
            records: 2
        }
    );
    assert_eq!(claim_reclaim(&mut db).unwrap(), ReclaimBatch::default());
}

#[test]
fn reclaim_turns_are_bounded_by_entries_and_bytes_and_resume() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    // 40 orphaned allocations of two files each: 80 files.
    for n in 1..=40 {
        let (job, attempt) = running(&db, n);
        let ids = request(n, &job, &attempt, 10, 10);
        reserve(&mut db, &ids).unwrap();
        mark_prepared(&mut db, &ids.result_id).unwrap();
        set_job_state(&db, &job, "failed");
    }
    let first = claim_reclaim(&mut db).unwrap();
    assert_eq!(first.objects.len(), RECLAIM_ENTRIES_PER_TURN);
    // Whole allocations per turn, so charges are released as early as possible.
    let released = confirm_reclaimed(&mut db, &first.objects).unwrap();
    assert_eq!(released, 32 * 20);
    let second = claim_reclaim(&mut db).unwrap();
    assert_eq!(second.objects.len(), 16);
    assert_eq!(confirm_reclaimed(&mut db, &second.objects).unwrap(), 8 * 20);
    assert_eq!(usage(&mut db).unwrap(), ResultUsage::default());
    // Byte bound: 600-KiB artifacts stop the turn once 1 MiB is reached.
    for n in 50..=52 {
        let (job, attempt) = running(&db, n);
        let ids = request(n, &job, &attempt, 614_400, 1);
        reserve(&mut db, &ids).unwrap();
        abandon(&mut db, &ids.result_id).unwrap();
        set_job_state(&db, &job, "canceled");
    }
    let turn = claim_reclaim(&mut db).unwrap();
    assert!(
        turn.objects.len() < 6 && !turn.objects.is_empty(),
        "{turn:?}"
    );
    assert_eq!(
        confirm_reclaimed(
            &mut db,
            &vec!["art_x".to_owned(); RECLAIM_ENTRIES_PER_TURN + 1]
        ),
        Err(CoreError::Conflict)
    );
}

#[test]
fn reference_lookups_report_only_recorded_names_and_shutdown_stops_new_charges() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let ids = request(1, &job, &attempt, 10, 10);
    reserve(&mut db, &ids).unwrap();
    let names = vec![
        ids.files[0].object_name.clone(),
        format!("art_{}", hex32(99)),
        ids.files[1].object_name.clone(),
    ];
    assert_eq!(
        known_objects(&mut db, &names).unwrap(),
        vec![names[0].clone(), names[2].clone()]
    );
    assert_eq!(
        known_objects(
            &mut db,
            &vec![names[0].clone(); RECLAIM_ENTRIES_PER_TURN + 1]
        ),
        Err(CoreError::Conflict)
    );
    let (job2, attempt2) = running(&db, 2);
    let (reply, response) = mpsc::sync_channel(1);
    handle(
        &mut db,
        ResultCommand::Reserve(request(2, &job2, &attempt2, 1, 1), reply),
        true,
    );
    assert_eq!(response.recv().unwrap(), Err(CoreError::Busy));
    let (reply, response) = mpsc::sync_channel(1);
    handle(&mut db, ResultCommand::Usage(reply), true);
    assert_eq!(response.recv().unwrap().unwrap().records, 1);
}

#[test]
fn a_preparation_of_this_session_is_never_reclaimed_while_it_may_still_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let ids = request(1, &job, &attempt, 100, 20);
    reserve(&mut db, &ids).unwrap();
    // The job ends while the preparer is still inside its native writes.
    set_job_state(&db, &job, "canceled");
    assert_eq!(claim_reclaim(&mut db).unwrap(), ReclaimBatch::default());
    assert_eq!(state(&db, &ids.result_id).as_deref(), Some("preparing"));
    // Its native work returned: now reclaimable, and only from `preparing`.
    abandon(&mut db, &ids.result_id).unwrap();
    assert_eq!(abandon(&mut db, &ids.result_id), Err(CoreError::Conflict));
    assert_eq!(claim_reclaim(&mut db).unwrap().objects.len(), 2);

    // A `preparing` allocation left by an earlier service session (restart
    // proved its preparer gone) is reclaimable without any abandon record.
    let (job2, attempt2) = running(&db, 2);
    let earlier = request(2, &job2, &attempt2, 100, 20);
    reserve(&mut db, &earlier).unwrap();
    set_job_state(&db, &job2, "interrupted");
    assert!(
        claim_reclaim(&mut db)
            .unwrap()
            .objects
            .iter()
            .all(|o| !o.ends_with(&hex32(2)))
    );
    db.execute_batch("INSERT INTO service_sessions VALUES('ins_earlier',0,1,'unclean');")
        .unwrap();
    db.execute(
        "UPDATE publication_allocations SET instance_id='ins_earlier' WHERE result_id=?1",
        [&earlier.result_id],
    )
    .unwrap();
    let batch = claim_reclaim(&mut db).unwrap();
    assert!(
        batch.objects.contains(&earlier.files[0].object_name),
        "{batch:?}"
    );
    assert_eq!(
        state(&db, &earlier.result_id).as_deref(),
        Some("reclaiming")
    );
}

#[test]
fn a_result_row_must_name_its_allocations_job_and_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let (other_job, other_attempt) = running(&db, 2);
    let ids = request(1, &job, &attempt, 10, 10);
    reserve(&mut db, &ids).unwrap();
    assert!(
        db.execute(
            "INSERT INTO results VALUES(?1,?2,?3,1,'1.0',1)",
            [&ids.result_id, &other_job, &other_attempt],
        )
        .is_err()
    );
    db.execute(
        "INSERT INTO results VALUES(?1,?2,?3,1,'1.0',1)",
        [&ids.result_id, &job, &attempt],
    )
    .unwrap();
}

#[test]
fn reclamation_refuses_once_no_session_is_active() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = store_at(&dir.path().join("s.sqlite3"));
    let (job, attempt) = running(&db, 1);
    let ids = request(1, &job, &attempt, 10, 10);
    reserve(&mut db, &ids).unwrap();
    set_job_state(&db, &job, "canceled");
    // The shutdown barrier marks this session clean while its preparer may
    // still be writing: the fence would otherwise see an "earlier" session.
    db.execute(
        "UPDATE service_sessions SET termination='clean' WHERE termination='active'",
        [],
    )
    .unwrap();
    assert_eq!(claim_reclaim(&mut db), Err(CoreError::Busy));
    assert_eq!(state(&db, &ids.result_id).as_deref(), Some("preparing"));
}
