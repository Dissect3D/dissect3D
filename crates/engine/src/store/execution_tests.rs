#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::*;

fn memory_store() -> Connection {
    let mut db = Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    initialize_schema(&mut db).unwrap();
    db
}

#[test]
fn fresh_execution_metadata_is_present_without_widening_credentials() {
    let db = memory_store();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8
    );
    for name in [
        "job_execution",
        "job_attempts",
        "resource_reservations",
        "job_events",
        "retry_bindings",
        "client_authorizations",
    ] {
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [name],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1,
            "{name}"
        );
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM credential_grants", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM client_authorizations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn lifecycle_metadata_initialization_rolls_back_with_ownership_markers() {
    let mut db = Connection::open_in_memory().unwrap();
    assert_eq!(
        initialize_schema_with_hook(&mut db, || Err(CoreError::StoreUnavailable)),
        Err(CoreError::StoreUnavailable)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE type='table'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

fn seed_queued(db: &Connection, job: &str, sequence: i64) {
    db.execute("INSERT OR IGNORE INTO credentials(client_id,enrollment_id,secret_digest,client_kind,created_at_ms) VALUES('cli_11111111111111111111111111111111','enr_11111111111111111111111111111111',zeroblob(32),'cli',1)", []).unwrap();
    db.execute("INSERT INTO jobs VALUES(?1,'cli_11111111111111111111111111111111',?2,17,'{exact captured resolution}','verified')", rusqlite::params![job,sequence]).unwrap();
    db.execute(
        "INSERT INTO job_acceptance_events VALUES(?1,?2,1)",
        rusqlite::params![job, sequence],
    )
    .unwrap();
    db.execute("INSERT INTO submission_bindings VALUES('cli_11111111111111111111111111111111','jobs.submit',?1,?1,1,zeroblob(32),'{}')", [job]).unwrap();
}

#[test]
fn v6_feature_ddl_preserves_captured_rows_and_rolls_back_as_one_transaction() {
    let mut db = memory_store();
    db.execute_batch("DROP TABLE results; DROP TABLE result_files; DROP TABLE publication_allocations; DROP TABLE publication_sequence; DROP TABLE job_events; DROP TABLE resource_reservations; DROP TABLE job_attempts; DROP TABLE retry_bindings; DROP TABLE job_execution; DROP TABLE client_authorizations; PRAGMA user_version=6;").unwrap();
    seed_queued(&db, "job_11111111111111111111111111111111", 7);
    let before: String = db
        .query_row("SELECT resolved_json FROM jobs", [], |r| r.get(0))
        .unwrap();
    {
        let tx = db.transaction().unwrap();
        add_execution_tables(&tx).unwrap();
        tx.pragma_update(None, "user_version", 7).unwrap();
        // Simulate failure after all DDL but before COMMIT.
    }
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='job_execution'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let tx = db.transaction().unwrap();
    add_execution_tables(&tx).unwrap();
    tx.pragma_update(None, "user_version", 7).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        db.query_row("SELECT resolved_json FROM jobs", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        db.query_row(
            "SELECT snapshot_revision,state,cleanup_status FROM job_execution",
            [],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?
            ))
        )
        .unwrap(),
        (1, "queued".into(), "confirmed".into())
    );
    assert_eq!(
        db.query_row(
            "SELECT acceptance_sequence,snapshot_revision FROM job_acceptance_events",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        )
        .unwrap(),
        (7, 1)
    );
    assert_eq!(db.query_row("SELECT canonicalization_version,hex(fingerprint),original_inputs_json FROM submission_bindings", [], |r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))).unwrap(),(1,"00".repeat(32),"{}".into()));
    assert!(db.execute("INSERT INTO submission_bindings VALUES('cli_11111111111111111111111111111111','jobs.submit','job_11111111111111111111111111111111','job_11111111111111111111111111111111',2,zeroblob(32),'{}')", []).is_err(),"v2 cannot claim an existing v1 key");
    assert!(
        db.query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
            .optional()
            .unwrap()
            .is_none()
    );
}

#[test]
fn dispatch_is_atomic_and_replay_keeps_the_original_clock_and_resource_set() {
    use super::execution::*;
    let mut db = memory_store();
    let job = "job_11111111111111111111111111111111";
    seed_queued(&db, job, 1);
    db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,timeout_ms,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued',25,'confirmed',17)",[job]).unwrap();
    let request = DispatchRequest {
        job_id: dissect3d_api::JobId::parse(job).unwrap(),
        expected_revision: 1,
        resolved_json: "{exact captured resolution}".into(),
        resources: vec!["cpu:controlled".into(), "device:second".into()],
    };
    let mut live = LiveAttempts::default();
    db.execute_batch("CREATE TRIGGER reject_event BEFORE INSERT ON job_events BEGIN SELECT RAISE(ABORT,'fault'); END;").unwrap();
    assert!(dispatch(&mut db, &mut live, request.clone()).is_err());
    assert_eq!(
        db.query_row("SELECT count(*) FROM job_attempts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM resource_reservations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER reject_event;").unwrap();
    let first = dispatch(&mut db, &mut live, request.clone()).unwrap();
    let second = dispatch(&mut db, &mut live, request.clone()).unwrap();
    for (value, prefix) in [
        (&first.attempt_id, "att_"),
        (&first.session_id, "ses_"),
        (&first.grant_id, "grt_"),
    ] {
        assert_eq!(value.len(), 36);
        assert!(value.starts_with(prefix));
    }
    assert_eq!(first.attempt_id, second.attempt_id);
    assert!(Arc::ptr_eq(&first.timing, &second.timing));
    std::thread::sleep(Duration::from_millis(35));
    assert!(second.timing.expired());
    let mut changed = request.clone();
    changed.resources.pop();
    assert!(matches!(
        dispatch(&mut db, &mut live, changed),
        Err(CoreError::Conflict)
    ));
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM job_events WHERE snapshot_revision=2",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM resource_reservations WHERE released=0",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(first.resolved_json, "{exact captured resolution}");
    assert_eq!(first.timeout_ms, Some(25));
}

#[test]
fn conflicting_resource_rolls_back_all_reservations_and_restart_retains_holds() {
    use super::execution::*;
    let mut db = memory_store();
    let mut live = LiveAttempts::default();
    for (suffix, sequence) in [("1", 1), ("2", 2)] {
        let job = format!("job_{}", suffix.repeat(32));
        seed_queued(&db, &job, sequence);
        db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued','confirmed',17)",[&job]).unwrap();
    }
    let request = |digit: &str, resources: Vec<String>| DispatchRequest {
        job_id: dissect3d_api::JobId::parse(format!("job_{}", digit.repeat(32))).unwrap(),
        expected_revision: 1,
        resolved_json: "{exact captured resolution}".into(),
        resources,
    };
    let first = dispatch(
        &mut db,
        &mut live,
        request("1", vec!["cpu:controlled".into()]),
    )
    .unwrap();
    assert!(
        dispatch(
            &mut db,
            &mut live,
            request("2", vec!["device:free".into(), "cpu:controlled".into()])
        )
        .is_err()
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM resource_reservations WHERE resource_id='device:free'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    initialize_schema(&mut db).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT state,cleanup_status,snapshot_revision FROM job_execution WHERE job_id=?1",
            [first.job_id.as_str()],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?
            ))
        )
        .unwrap(),
        ("interrupted".into(), "pending".into(), 3)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM resource_reservations WHERE released=0",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM job_attempts", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let mut restarted = LiveAttempts::default();
    assert!(matches!(
        dispatch(
            &mut db,
            &mut restarted,
            request("1", vec!["cpu:controlled".into()])
        ),
        Err(CoreError::Conflict)
    ));
}

#[test]
fn authorization_is_explicit_same_creator_repeat_safe_and_never_revives_revocation() {
    use super::reauthorization::*;
    let mut db = memory_store();
    let identity = read_identity(&db).unwrap();
    let client = ClientId::parse("cli_11111111111111111111111111111111").unwrap();
    let token = TokenDigest::new([7; 32]);
    enroll(
        &mut db,
        VerifiedEnrollment::new(
            current_owner_identity().unwrap(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            dissect3d_api::EnrollmentId::parse("enr_11111111111111111111111111111111").unwrap(),
            client.clone(),
            token.clone(),
        ),
    )
    .unwrap();
    let before = authenticate(&mut db, client.clone(), token.clone()).unwrap();
    assert_eq!(before.granted_operations.len(), 5);
    let request = || VerifiedAuthorization {
        owner: current_owner_identity().unwrap(),
        installation_id: identity.installation_id.clone(),
        instance_id: identity.instance_id.clone(),
        client_id: client.clone(),
        token_digest: token.clone(),
        authorization_id: "aut_11111111111111111111111111111111".into(),
    };
    let mut wrong = request();
    wrong.token_digest = TokenDigest::new([8; 32]);
    assert!(matches!(
        authorize(&mut db, wrong),
        Err(CoreError::Unauthorized)
    ));
    let first = authorize(&mut db, request()).unwrap();
    assert!(!first.replayed);
    assert_eq!(first.granted_operations.len(), 15);
    assert_eq!(first.client_id, client);
    let replay = authorize(&mut db, request()).unwrap();
    assert!(replay.replayed);
    assert_eq!(first.granted_operations, replay.granted_operations);
    let context = authenticate(&mut db, client.clone(), token.clone()).unwrap();
    assert!(
        context
            .granted_operations
            .iter()
            .any(|g| g == "jobs.cancel")
    );
    assert_eq!(
        db.query_row("SELECT grant_policy FROM credentials", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "core-v1"
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM credential_grants", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        5
    );
    revoke_self(&mut db, context).unwrap();
    assert!(matches!(
        authorize(&mut db, request()),
        Err(CoreError::Unauthorized)
    ));
    assert!(matches!(
        authenticate(&mut db, client, token),
        Err(CoreError::Unauthorized)
    ));
}

#[test]
fn cancellation_is_creator_scoped_repeat_safe_and_holds_active_resources() {
    use super::execution::*;
    let mut db = memory_store();
    let mut live = LiveAttempts::default();
    let one = "job_11111111111111111111111111111111";
    let two = "job_22222222222222222222222222222222";
    for (job, seq) in [(one, 1), (two, 2)] {
        seed_queued(&db, job, seq);
        db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued','confirmed',17)",[job]).unwrap();
    }
    for grant in crate::credentials::SUBMISSION_GRANTS {
        db.execute(
            "INSERT INTO credential_grants VALUES('cli_11111111111111111111111111111111',?1)",
            [grant],
        )
        .unwrap();
    }
    db.execute("UPDATE credentials SET grant_policy='submission-v1'", [])
        .unwrap();
    let client = ClientId::parse("cli_11111111111111111111111111111111").unwrap();
    let context = AuthContext {
        installation_id: read_identity(&db).unwrap().installation_id,
        client_id: client.clone(),
        granted_operations: vec![],
    };
    assert!(matches!(
        cancel(
            &mut db,
            &context,
            &dissect3d_api::JobId::parse(one).unwrap()
        ),
        Err(CoreError::Unauthorized)
    ));
    db.execute("INSERT INTO client_authorizations VALUES('aut_11111111111111111111111111111111',?1,'execution-v1',1)",[client.as_str()]).unwrap();
    let mut wrong = context.clone();
    wrong.client_id = ClientId::parse("cli_22222222222222222222222222222222").unwrap();
    assert!(matches!(
        cancel(&mut db, &wrong, &dissect3d_api::JobId::parse(one).unwrap()),
        Err(CoreError::Unauthorized)
    ));
    assert_eq!(
        cancel(
            &mut db,
            &context,
            &dissect3d_api::JobId::parse(one).unwrap()
        )
        .unwrap(),
        "canceled_before_dispatch"
    );
    assert_eq!(
        cancel(
            &mut db,
            &context,
            &dissect3d_api::JobId::parse(one).unwrap()
        )
        .unwrap(),
        "already_terminal"
    );
    dispatch(
        &mut db,
        &mut live,
        DispatchRequest {
            job_id: dissect3d_api::JobId::parse(two).unwrap(),
            expected_revision: 1,
            resolved_json: "{exact captured resolution}".into(),
            resources: vec!["cpu:controlled".into()],
        },
    )
    .unwrap();
    assert_eq!(
        cancel(
            &mut db,
            &context,
            &dissect3d_api::JobId::parse(two).unwrap()
        )
        .unwrap(),
        "requested"
    );
    let revision: i64 = db
        .query_row(
            "SELECT snapshot_revision FROM job_execution WHERE job_id=?1",
            [two],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        cancel(
            &mut db,
            &context,
            &dissect3d_api::JobId::parse(two).unwrap()
        )
        .unwrap(),
        "requested"
    );
    assert_eq!(
        db.query_row(
            "SELECT snapshot_revision FROM job_execution WHERE job_id=?1",
            [two],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        revision
    );
    initialize_schema(&mut db).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT state,cancel_requested_at_ms IS NOT NULL FROM job_execution WHERE job_id=?1",
            [two],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        )
        .unwrap(),
        // Durable cancellation intent survives restart (WE-005, ENG-031).
        ("cancel_requested".into(), true)
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM resource_reservations WHERE released=0",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[cfg(unix)]
#[test]
fn dropped_dispatch_reply_retains_store_owned_timing() {
    use super::execution::*;
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("actor");
    let root =
        OwnedRoot::create_private(&path, dissect3d_platform::RootPurpose::EngineData).unwrap();
    let db = open_database(&root, &CorePolicy::default()).unwrap();
    let job = "job_11111111111111111111111111111111";
    seed_queued(&db, job, 1);
    db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,timeout_ms,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued',25,'confirmed',17)",[job]).unwrap();
    drop(db);
    let lease = AuthorityLease::acquire(&root).unwrap();
    let store = Store::open(root, lease, &CorePolicy::default()).unwrap();
    let (reply, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    store
        .sender
        .send(Command::Execution(ExecutionCommand::Dispatch(
            DispatchRequest {
                job_id: dissect3d_api::JobId::parse(job).unwrap(),
                expected_revision: 1,
                resolved_json: "{exact captured resolution}".into(),
                resources: vec!["cpu:controlled".into()],
            },
            reply,
        )))
        .unwrap();
    store.identity().unwrap(); // Barrier after the actor processed the abandoned request.
    let db = Connection::open(path.join(DATABASE_NAME)).unwrap();
    let attempt: String = db
        .query_row("SELECT attempt_id FROM job_attempts", [], |r| r.get(0))
        .unwrap();
    let first = store.attempt_timing(attempt.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(35));
    let recovered = store.attempt_timing(attempt).unwrap();
    assert!(Arc::ptr_eq(&first, &recovered));
    assert!(recovered.expired());
    assert_eq!(first.started(), recovered.started());
    assert_eq!(first.deadline(), recovered.deadline());
}

#[test]
fn malformed_dispatch_revision_cannot_panic_or_modify_a_live_attempt() {
    use super::execution::*;
    let mut db = memory_store();
    let mut live = LiveAttempts::default();
    let job = "job_11111111111111111111111111111111";
    seed_queued(&db, job, 1);
    db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued','confirmed',17)",[job]).unwrap();
    let mut req = DispatchRequest {
        job_id: dissect3d_api::JobId::parse(job).unwrap(),
        expected_revision: 1,
        resolved_json: "{exact captured resolution}".into(),
        resources: vec!["cpu:controlled".into()],
    };
    dispatch(&mut db, &mut live, req.clone()).unwrap();
    req.expected_revision = i64::MAX;
    assert!(matches!(
        dispatch(&mut db, &mut live, req),
        Err(CoreError::Conflict)
    ));
}

#[test]
fn actual_v6_upgrade_keeps_old_backup_and_exact_rows_with_external_input_references() {
    let parent = tempfile::tempdir().unwrap();
    let path = parent.path().join("v6");
    let root =
        OwnedRoot::create_private(&path, dissect3d_platform::RootPurpose::EngineData).unwrap();
    let mut db = open_database(&root, &CorePolicy::default()).unwrap();
    db.execute_batch("DROP TABLE results; DROP TABLE result_files; DROP TABLE publication_allocations; DROP TABLE publication_sequence; DROP TABLE job_events; DROP TABLE resource_reservations; DROP TABLE job_attempts; DROP TABLE retry_bindings; DROP TABLE job_execution; DROP TABLE client_authorizations;
      ALTER TABLE submission_bindings RENAME TO bindings_v7;
      CREATE TABLE submission_bindings(client_id TEXT NOT NULL REFERENCES credentials(client_id),operation TEXT NOT NULL CHECK(operation='jobs.submit'),idempotency_key TEXT NOT NULL,job_id TEXT NOT NULL REFERENCES jobs(job_id),canonicalization_version INTEGER NOT NULL CHECK(canonicalization_version=1),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),original_inputs_json TEXT NOT NULL,PRIMARY KEY(client_id,operation,idempotency_key));
      DROP TABLE bindings_v7; PRAGMA user_version=6;").unwrap();
    let job = "job_11111111111111111111111111111111";
    seed_queued(&db, job, 7);
    db.execute_batch("INSERT INTO captured_inputs VALUES('inp_11111111111111111111111111111111','cli_11111111111111111111111111111111','application/octet-stream',64,zeroblob(32),1,999999,'complete');
       INSERT INTO job_inputs VALUES('job_11111111111111111111111111111111','inp_11111111111111111111111111111111'); UPDATE job_sequence SET value=7;").unwrap();
    let installation = read_identity(&db).unwrap().installation_id;
    let prior = RelativePath::parse("recovery/metadata-v6-upgrade.sqlite3").unwrap();
    root.write_atomic(&prior, b"preserved earlier image")
        .unwrap();
    run_migrations(&mut db, &root, &CORE_MIGRATIONS).unwrap();
    assert_eq!(read_identity(&db).unwrap().installation_id, installation);
    assert_eq!(
        std::fs::read(path.join(prior.as_str())).unwrap(),
        b"preserved earlier image"
    );
    assert_eq!(
        db.query_row("SELECT value FROM job_sequence", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM job_inputs", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT resolved_json FROM jobs", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "{exact captured resolution}"
    );
    let backup = Connection::open_with_flags(
        path.join("recovery/metadata-v8-upgrade.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        backup
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        backup
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    assert_eq!(
        backup
            .query_row("SELECT count(*) FROM job_inputs", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(
        db.query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
            .optional()
            .unwrap()
            .is_none()
    );
}

#[test]
fn event_retention_is_bounded_without_erasing_the_current_snapshot() {
    let mut db = memory_store();
    let job = "job_11111111111111111111111111111111";
    seed_queued(&db, job, 1);
    db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued','confirmed',17)",[job]).unwrap();
    for revision in 2..=300 {
        let tx = db.transaction().unwrap();
        tx.execute(
            "UPDATE job_execution SET snapshot_revision=?2 WHERE job_id=?1",
            rusqlite::params![job, revision],
        )
        .unwrap();
        super::execution::record_event(&tx, job).unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(
        db.query_row(
            "SELECT count(*),min(snapshot_revision),max(snapshot_revision) FROM job_events",
            [],
            |r| Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?
            ))
        )
        .unwrap(),
        (256, 45, 300)
    );
    assert_eq!(
        db.query_row("SELECT snapshot_revision FROM job_execution", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        300
    );
    assert_eq!(
        db.query_row(
            "SELECT snapshot_revision FROM job_acceptance_events",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

// 2026-11-18 event-history retention (ENG-029, ENG-046): count and byte bounds,
// oldest first, newest kept, contiguous range; job records keep the facts.
fn retained(db: &Connection, job: &str) -> (i64, i64, i64, i64) {
    db.query_row(
        "SELECT count(*),min(snapshot_revision),max(snapshot_revision),
                coalesce(sum(length(CAST(snapshot_json AS BLOB))),0)
         FROM job_events WHERE job_id=?1",
        [job],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .unwrap()
}

fn bump(db: &mut Connection, job: &str, phase: &str, retention: super::execution::EventRetention) {
    let tx = db.transaction().unwrap();
    tx.execute(
        "UPDATE job_execution SET snapshot_revision=snapshot_revision+1,phase=?2 WHERE job_id=?1",
        rusqlite::params![job, phase],
    )
    .unwrap();
    super::execution::record_event_within(&tx, job, retention).unwrap();
    tx.commit().unwrap();
}

fn queued_job(db: &Connection, job: &str, sequence: i64) {
    seed_queued(db, job, sequence);
    db.execute("INSERT INTO job_execution(job_id,snapshot_revision,state,phase,cleanup_status,updated_at_ms) VALUES(?1,1,'queued','queued','confirmed',17)",[job]).unwrap();
}

#[test]
fn event_history_count_and_byte_bounds_prune_oldest_first_and_stay_contiguous() {
    use super::execution::{EVENT_RETENTION, EventRetention};
    // The published per-job bounds.
    assert_eq!(EVENT_RETENTION.revisions, 256);
    assert_eq!(EVENT_RETENTION.bytes, 262_144);
    let mut db = memory_store();
    let counted = "job_11111111111111111111111111111111";
    let sized = "job_22222222222222222222222222222222";
    queued_job(&db, counted, 1);
    queued_job(&db, sized, 2);
    // Count bound alone (bytes ample): exactly the newest 4 revisions remain.
    let by_count = EventRetention {
        revisions: 4,
        bytes: 262_144,
    };
    for _ in 0..10 {
        bump(&mut db, counted, "running", by_count);
    }
    let (count, min, max, _) = retained(&db, counted);
    assert_eq!((count, min, max), (4, 8, 11));
    // Byte bound alone (count ample): the oldest events go first until the
    // retained bytes fit; the newest always stays and no revision is skipped.
    let one = {
        bump(&mut db, sized, &"p".repeat(64), EVENT_RETENTION);
        retained(&db, sized).3
    };
    let by_bytes = EventRetention {
        revisions: 256,
        bytes: one * 3 + one / 2,
    };
    for _ in 0..9 {
        bump(&mut db, sized, &"p".repeat(64), by_bytes);
        let (count, min, max, bytes) = retained(&db, sized);
        assert!(bytes <= by_bytes.bytes, "{bytes}");
        assert_eq!(count, max - min + 1, "contiguous");
    }
    let (count, min, max, _) = retained(&db, sized);
    assert_eq!((count, min, max), (3, 9, 11));
    // The other job's history is untouched by this job's pruning.
    assert_eq!(retained(&db, counted).0, 4);
    // A single newest event larger than the byte bound is still kept.
    let tiny = EventRetention {
        revisions: 256,
        bytes: 1,
    };
    bump(&mut db, sized, "after", tiny);
    let (count, min, max, _) = retained(&db, sized);
    assert_eq!((count, min, max), (1, 12, 12));
    let current: i64 = db
        .query_row(
            "SELECT snapshot_revision FROM job_execution WHERE job_id=?1",
            [sized],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(current, 12);
}

#[test]
fn pruned_events_never_erase_terminal_cancel_or_cleanup_facts() {
    use super::execution::EventRetention;
    let mut db = memory_store();
    let job = "job_11111111111111111111111111111111";
    queued_job(&db, job, 1);
    let tx = db.transaction().unwrap();
    tx.execute(
        "UPDATE job_execution SET snapshot_revision=2,state='canceled',phase='canceled',
             cancel_requested_at_ms=99,cleanup_status='fault',cleanup_reason='cleanup_deadline',
             outcome_code='engine_restarted' WHERE job_id=?1",
        [job],
    )
    .unwrap();
    super::execution::record_event(&tx, job).unwrap();
    tx.commit().unwrap();
    let small = EventRetention {
        revisions: 2,
        bytes: 262_144,
    };
    for _ in 0..5 {
        bump(&mut db, job, "canceled", small);
    }
    // The terminal revision's event is gone; the job record still holds every fact.
    assert_eq!(retained(&db, job).1, 6);
    assert_eq!(
        db.query_row(
            "SELECT state,cancel_requested_at_ms,cleanup_status,cleanup_reason,outcome_code,
                    snapshot_revision
             FROM job_execution WHERE job_id=?1",
            [job],
            |r| Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?
            ))
        )
        .unwrap(),
        (
            "canceled".into(),
            99,
            "fault".into(),
            "cleanup_deadline".into(),
            "engine_restarted".into(),
            7
        )
    );
    // The newest retained event carries the same terminal facts.
    let newest: String = db
        .query_row(
            "SELECT snapshot_json FROM job_events WHERE job_id=?1 AND snapshot_revision=7",
            [job],
            |r| r.get(0),
        )
        .unwrap();
    let newest: serde_json::Value = serde_json::from_str(&newest).unwrap();
    assert_eq!(newest["state"], "canceled");
    assert_eq!(newest["cleanup_status"], "fault");
    assert_eq!(newest["cancel_requested_at_ms"], 99);
}

#[test]
fn oversized_lifecycle_fields_are_rejected_before_commit() {
    let mut db = memory_store();
    let job = "job_11111111111111111111111111111111";
    queued_job(&db, job, 1);
    for (column, value) in [
        ("progress_json", format!("\"{}\"", "x".repeat(16_383))),
        ("cleanup_reason", "r".repeat(129)),
        ("outcome_code", "o".repeat(129)),
    ] {
        let tx = db.transaction().unwrap();
        tx.execute(
            &format!(
                "UPDATE job_execution SET {column}=?2,snapshot_revision=snapshot_revision+1
                 WHERE job_id=?1"
            ),
            rusqlite::params![job, value],
        )
        .unwrap();
        assert!(
            matches!(
                super::execution::record_event(&tx, job),
                Err(CoreError::Conflict)
            ),
            "{column}"
        );
        drop(tx);
    }
    // Every limit-sized value is accepted.
    let tx = db.transaction().unwrap();
    tx.execute(
        "UPDATE job_execution SET progress_json=?2,cleanup_reason=?3,outcome_code=?4,
             snapshot_revision=snapshot_revision+1 WHERE job_id=?1",
        rusqlite::params![
            job,
            format!("\"{}\"", "x".repeat(16_382)),
            "r".repeat(128),
            "o".repeat(128)
        ],
    )
    .unwrap();
    super::execution::record_event(&tx, job).unwrap();
    tx.commit().unwrap();
    assert_eq!(retained(&db, job).0, 1);
}
