//! WE-003 exact linked retry at the Store seam (2026-11-17). Dispatch stays
//! inactive; terminal sources come from real cancellation or isolated SQL setup.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only module behind a compound cfg(all(test, ...)) gate that clippy test \
              allowances do not recognize; Rule 6 permits unwrap in tests"
)]
#![expect(
    clippy::disallowed_methods,
    reason = "Fault and migration tests open the SQLite file directly to plant or inspect states \
              the store API cannot express; production opens only via store/schema.rs"
)]
use super::*;
use crate::store::retry::RetryPrerequisites;
use crate::submission::admission::PreparedAdmission;

const KEY: &str = "retry-key";

pub(super) fn db(f: &Fixture) -> Connection {
    Connection::open(f.root.path().join(DATABASE_NAME)).unwrap()
}
/// Explicit same-client execution authorization, then a fresh context.
pub(super) fn authorize(f: &Fixture) -> AuthContext {
    let identity = f.store.identity().unwrap();
    let (client, digest) = fixture_credentials();
    f.store
        .authorize_execution(reauthorization::VerifiedAuthorization {
            owner: current_owner_identity().unwrap(),
            installation_id: identity.installation_id,
            instance_id: identity.instance_id,
            client_id: client.clone(),
            token_digest: digest.clone(),
            authorization_id: "aut_11111111111111111111111111111111".into(),
        })
        .unwrap();
    f.store.authenticate(client, digest).unwrap()
}
pub(super) fn prerequisites(f: &Fixture) -> RetryPrerequisites {
    RetryPrerequisites {
        prepared: Some(PreparedAdmission::from_verified_fixture(
            &f.prepared.readiness,
        )),
        reconciled: true,
    }
}
pub(super) fn accept(f: &Fixture, key: &str) -> AcceptanceReceipt {
    let req = f.request(&f.capture());
    f.store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse(key).unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap()
}
/// A real queued cancellation: terminal `canceled`, cleanup confirmed.
pub(super) fn canceled_source(f: &Fixture, auth: &AuthContext, key: &str) -> JobId {
    let job = accept(f, key).job_id;
    assert_eq!(
        f.store
            .cancel_execution_job(auth.clone(), job.clone())
            .unwrap(),
        "canceled_before_dispatch"
    );
    job
}
pub(super) fn retry(
    f: &Fixture,
    auth: &AuthContext,
    key: &str,
    source: &JobId,
) -> Result<ExecutionAcceptance, crate::submission::SubmissionError> {
    f.store.retry_job(
        auth.clone(),
        IdempotencyKey::parse(key).unwrap(),
        source.clone(),
        prerequisites(f),
    )
}
type JobRow = (String, String, i64, i64, String, String);
type ExecutionRow = (
    i64,
    String,
    String,
    Option<i64>,
    Option<i64>,
    String,
    Option<String>,
    Option<String>,
    i64,
);
fn job_row(db: &Connection, job: &str) -> (JobRow, ExecutionRow, Vec<String>) {
    let job_row = db
        .query_row(
            "SELECT job_id,client_id,acceptance_sequence,created_at_ms,resolved_json,storage_status
             FROM jobs WHERE job_id=?1",
            [job],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .unwrap();
    let execution = db
        .query_row(
            "SELECT snapshot_revision,state,phase,timeout_ms,cancel_requested_at_ms,cleanup_status,
                    outcome_code,retry_of,updated_at_ms
             FROM job_execution WHERE job_id=?1",
            [job],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                ))
            },
        )
        .unwrap();
    let inputs = db
        .prepare("SELECT input_id FROM job_inputs WHERE job_id=?1 ORDER BY input_id")
        .unwrap()
        .query_map([job], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    (job_row, execution, inputs)
}
fn count(db: &Connection, sql: &str) -> i64 {
    db.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn retry_copies_exact_resolution_policy_and_inputs_and_never_changes_the_source() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let db = db(&f);
    let before = job_row(&db, source.as_str());
    let accepted = retry(&f, &auth, KEY, &source).unwrap();
    assert!(!accepted.replayed);
    assert_ne!(accepted.job_id, source);
    assert_eq!(accepted.retry_of.as_ref(), Some(&source));
    assert_eq!(accepted.acceptance_sequence, 2);
    assert_eq!(accepted.snapshot_revision, 1);
    let (job, execution, inputs) = job_row(&db, accepted.job_id.as_str());
    // Byte-for-byte resolution and inputs; same policy; queued revision 1.
    assert_eq!(job.4, before.0.4);
    assert_eq!(job.1, before.0.1);
    assert_eq!(job.5, "verified");
    assert_eq!(inputs, before.2);
    assert_eq!(execution.3, before.1.3);
    assert_eq!(execution.3, Some(1200));
    assert_eq!(
        (execution.0, execution.1.as_str(), execution.2.as_str()),
        (1, "queued", "queued")
    );
    assert_eq!(execution.5, "confirmed");
    assert_eq!(execution.7.as_deref(), Some(source.as_str()));
    assert_eq!(
        serde_json::to_string(&accepted.resolved).unwrap(),
        before.0.4,
        "receipt resolution is the stored resolution"
    );
    // The source outcome and every source fact are unchanged.
    assert_eq!(job_row(&db, source.as_str()), before);
    // One acceptance event and one retry binding; no captured bytes added.
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM job_acceptance_events WHERE acceptance_sequence=2"
        ),
        1
    );
    assert_eq!(count(&db, "SELECT count(*) FROM retry_bindings"), 1);
    assert_eq!(
        count(&db, "SELECT count(DISTINCT input_id) FROM job_inputs"),
        1
    );
    // The private execution snapshot reports the link and exact policy.
    let snapshot = f
        .store
        .execution_job_snapshot(auth, accepted.job_id.clone())
        .unwrap();
    assert_eq!(snapshot.summary.retry_of, Some(source));
    assert_eq!(snapshot.summary.execution_policy.timeout_ms, Some(1200));
    assert_eq!(snapshot.resolved, accepted.resolved);
}

#[test]
fn same_key_replays_without_a_sequence_and_another_source_conflicts() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let other = canceled_source(&f, &auth, "other");
    let first = retry(&f, &auth, KEY, &source).unwrap();
    let replay = retry(&f, &auth, KEY, &source).unwrap();
    assert!(replay.replayed);
    assert_eq!(
        ExecutionAcceptance {
            replayed: false,
            ..replay.clone()
        },
        first
    );
    assert_eq!(
        retry(&f, &auth, KEY, &other).unwrap_err().code,
        ErrorCode::IdempotencyConflict
    );
    let db = db(&f);
    assert_eq!(
        count(&db, "SELECT value FROM job_sequence"),
        first.acceptance_sequence
    );
    assert_eq!(count(&db, "SELECT count(*) FROM jobs"), 3);
    // Replay never consults readiness, reconciliation or free space.
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        free_reserve: u64::MAX,
        ..Default::default()
    });
    let replay = f
        .store
        .retry_job(
            auth,
            IdempotencyKey::parse(KEY).unwrap(),
            source,
            RetryPrerequisites {
                prepared: None,
                reconciled: false,
            },
        )
        .unwrap();
    assert_eq!(replay.job_id, first.job_id);
}

#[test]
fn replay_works_at_the_shared_lifetime_binding_cap_which_counts_both_operations() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let first = retry(&f, &auth, KEY, &source).unwrap();
    // One submission binding plus one retry binding fill a cap of two.
    f.store.set_test_job_limits(admission::AcceptanceLimits {
        bindings: 2,
        ..Default::default()
    });
    let fresh = retry(&f, &auth, "another-key", &source).unwrap_err();
    assert_eq!(fresh.limit, Some("submission_bindings_max"));
    let req = f.request(&f.capture());
    let submission = f
        .store
        .accept_execution_job(
            f.auth.clone(),
            IdempotencyKey::parse("blocked-submission").unwrap(),
            req.clone(),
            f.candidate(&req),
        )
        .unwrap_err();
    assert_eq!(submission.limit, Some("submission_bindings_max"));
    let replay = retry(&f, &auth, KEY, &source).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.job_id, first.job_id);
}

#[test]
fn missing_or_revoked_retry_grant_is_refused_for_fresh_work_and_replay() {
    let f = Fixture::new();
    // Submission-only credential: no `jobs.retry` grant.
    let source = accept(&f, "source").job_id;
    assert_eq!(
        retry(&f, &f.auth, KEY, &source).unwrap_err().code,
        ErrorCode::Unauthorized
    );
    let auth = authorize(&f);
    f.store
        .cancel_execution_job(auth.clone(), source.clone())
        .unwrap();
    retry(&f, &auth, KEY, &source).unwrap();
    f.store.revoke_self(auth.clone()).unwrap();
    for key in [KEY, "fresh-after-revocation"] {
        assert_eq!(
            retry(&f, &auth, key, &source).unwrap_err().code,
            ErrorCode::Unauthorized
        );
    }
}

#[test]
fn another_creators_job_reads_as_not_found() {
    let f = Fixture::new();
    let owner = authorize(&f);
    let source = canceled_source(&f, &owner, "source");
    let identity = f.store.identity().unwrap();
    let client = ClientId::parse("cli_33333333333333333333333333333333").unwrap();
    let digest = TokenDigest::new([3; 32]);
    f.store
        .enroll(VerifiedEnrollment::new_submission_access(
            current_owner_identity().unwrap(),
            identity.installation_id.clone(),
            identity.instance_id.clone(),
            EnrollmentId::parse("enr_33333333333333333333333333333333").unwrap(),
            client.clone(),
            digest.clone(),
        ))
        .unwrap();
    f.store
        .authorize_execution(reauthorization::VerifiedAuthorization {
            owner: current_owner_identity().unwrap(),
            installation_id: identity.installation_id,
            instance_id: identity.instance_id,
            client_id: client.clone(),
            token_digest: digest.clone(),
            authorization_id: "aut_33333333333333333333333333333333".into(),
        })
        .unwrap();
    let stranger = f.store.authenticate(client, digest).unwrap();
    assert_eq!(
        retry(&f, &stranger, KEY, &source).unwrap_err().code,
        ErrorCode::NotFound
    );
    let missing = JobId::parse("job_ffffffffffffffffffffffffffffffff").unwrap();
    assert_eq!(
        retry(&f, &owner, KEY, &missing).unwrap_err().code,
        ErrorCode::NotFound
    );
}

pub(super) fn dispatch(f: &Fixture, job: &JobId) -> execution::DispatchRecord {
    let resolved: String = db(f)
        .query_row(
            "SELECT resolved_json FROM jobs WHERE job_id=?1",
            [job.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    f.store
        .dispatch_attempt(execution::DispatchRequest {
            job_id: job.clone(),
            expected_revision: 1,
            resolved_json: resolved,
            resources: vec!["cpu:fixture".into()],
        })
        .unwrap()
}

#[test]
fn every_nonterminal_source_state_is_refused() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let queued = accept(&f, "queued").job_id;
    let running = accept(&f, "running").job_id;
    dispatch(&f, &running);
    for (job, state) in [(&queued, "queued"), (&running, "running")] {
        assert_eq!(
            retry(&f, &auth, state, job).unwrap_err().code,
            ErrorCode::JobNotTerminal,
            "{state}"
        );
    }
    assert_eq!(
        f.store
            .cancel_execution_job(auth.clone(), running.clone())
            .unwrap(),
        "requested"
    );
    assert_eq!(
        retry(&f, &auth, "cancel-requested", &running)
            .unwrap_err()
            .code,
        ErrorCode::JobNotTerminal
    );
    assert_eq!(count(&db(&f), "SELECT count(*) FROM retry_bindings"), 0);
}

#[test]
fn unresolved_cleanup_or_held_reservation_is_refused_before_acceptance() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = accept(&f, "source").job_id;
    dispatch(&f, &source);
    // Restart interrupts the attempt, leaving cleanup pending and the hold.
    let Fixture {
        _parent,
        root,
        store,
        auth: submit,
        prepared,
    } = f;
    drop(store);
    let reopened = OwnedRoot::open(root.path(), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&reopened).unwrap();
    let f = Fixture {
        _parent,
        root,
        store: Store::open(reopened, lease, &CorePolicy::default()).unwrap(),
        auth: submit,
        prepared,
    };
    let db = db(&f);
    assert_eq!(
        db.query_row(
            "SELECT state FROM job_execution WHERE job_id=?1",
            [source.as_str()],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "interrupted"
    );
    let refused = |key: &str| retry(&f, &auth, key, &source).unwrap_err().code;
    assert_eq!(refused("pending"), ErrorCode::CleanupUnconfirmed);
    // Isolated setup for each remaining unresolved fact in turn.
    let attempt: String = db
        .query_row(
            "SELECT attempt_id FROM job_attempts WHERE job_id=?1",
            [source.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    for (setup, label) in [
        (
            "UPDATE job_execution SET cleanup_status='confirmed' WHERE job_id=?1;
             UPDATE job_attempts SET cleanup_status='confirmed' WHERE attempt_id=?2;",
            "unreleased",
        ),
        (
            "UPDATE resource_reservations SET released=1 WHERE attempt_id=?2;
             UPDATE job_execution SET cleanup_status='fault' WHERE job_id=?1;",
            "job-fault",
        ),
        (
            "UPDATE job_execution SET cleanup_status='confirmed' WHERE job_id=?1;
             UPDATE job_attempts SET cleanup_status='fault' WHERE attempt_id=?2;",
            "attempt-fault",
        ),
    ] {
        for statement in setup.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            // ?1 is the source job and ?2 the attempt.
            let mut statement = db.prepare(statement).unwrap();
            if statement.parameter_count() == 1 {
                statement.execute([source.as_str()]).unwrap();
            } else {
                statement
                    .execute([source.as_str(), attempt.as_str()])
                    .unwrap();
            }
        }
        assert_eq!(refused(label), ErrorCode::CleanupUnconfirmed, "{label}");
    }
    assert_eq!(count(&db, "SELECT count(*) FROM retry_bindings"), 0);
    db.execute(
        "UPDATE job_attempts SET cleanup_status='confirmed' WHERE attempt_id=?1",
        [attempt.as_str()],
    )
    .unwrap();
    // Established cleanup: an interrupted source is retryable explicitly.
    let accepted = retry(&f, &auth, "resolved", &source).unwrap();
    assert_eq!(accepted.retry_of, Some(source));
}

#[test]
fn unavailable_input_storage_fault_or_unprepared_resolution_is_refused() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let db = db(&f);
    let input: String = db
        .query_row(
            "SELECT input_id FROM job_inputs WHERE job_id=?1",
            [source.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    let unavailable = |key: &str, prerequisites: RetryPrerequisites| {
        f.store
            .retry_job(
                auth.clone(),
                IdempotencyKey::parse(key).unwrap(),
                source.clone(),
                prerequisites,
            )
            .unwrap_err()
            .code
    };
    // Normal empty catalog: nothing is prepared.
    let none = RetryPrerequisites {
        prepared: None,
        reconciled: true,
    };
    assert_eq!(
        unavailable("unprepared", none),
        ErrorCode::RetryPrerequisiteUnavailable
    );
    for (setup, undo, label) in [
        (
            "UPDATE captured_inputs SET cleanup_state='deleting' WHERE input_id=?1",
            "UPDATE captured_inputs SET cleanup_state='complete' WHERE input_id=?1",
            "input-cleanup",
        ),
        (
            "UPDATE captured_inputs SET sha256=zeroblob(32) WHERE input_id=?1",
            "",
            "input-identity",
        ),
    ] {
        let original: Vec<u8> = db
            .query_row(
                "SELECT sha256 FROM captured_inputs WHERE input_id=?1",
                [input.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        db.execute(setup, [input.as_str()]).unwrap();
        assert_eq!(
            unavailable(label, prerequisites(&f)),
            ErrorCode::RetryPrerequisiteUnavailable,
            "{label}"
        );
        if undo.is_empty() {
            db.execute(
                "UPDATE captured_inputs SET sha256=?2 WHERE input_id=?1",
                rusqlite::params![input.as_str(), original],
            )
            .unwrap();
        } else {
            db.execute(undo, [input.as_str()]).unwrap();
        }
    }
    db.execute(
        "UPDATE jobs SET storage_status='storage_integrity_fault' WHERE job_id=?1",
        [source.as_str()],
    )
    .unwrap();
    assert_eq!(
        unavailable("storage-fault", prerequisites(&f)),
        ErrorCode::RetryPrerequisiteUnavailable
    );
    db.execute(
        "UPDATE jobs SET storage_status='verified' WHERE job_id=?1",
        [source.as_str()],
    )
    .unwrap();
    // A prepared resolution that differs from the retained one is not used.
    let mut other = prerequisites(&f);
    let mut readiness = f.prepared.readiness.clone();
    readiness.snapshot.check_id = "another-prepared-check".into();
    other.prepared = Some(PreparedAdmission::from_verified_fixture(&readiness));
    assert_eq!(
        unavailable("other-readiness", other),
        ErrorCode::RetryPrerequisiteUnavailable
    );
    assert_eq!(
        unavailable(
            "recovering",
            RetryPrerequisites {
                reconciled: false,
                ..prerequisites(&f)
            }
        ),
        ErrorCode::EngineRecovering
    );
    assert_eq!(count(&db, "SELECT count(*) FROM retry_bindings"), 0);
    assert!(retry(&f, &auth, "restored", &source).is_ok());
}

#[test]
fn every_terminal_outcome_is_retryable_and_a_retry_links_to_its_immediate_source() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let db = db(&f);
    for state in ["succeeded", "partial", "failed", "interrupted"] {
        let job = accept(&f, state).job_id;
        db.execute(
            "UPDATE job_execution SET state=?2,phase=?2 WHERE job_id=?1",
            rusqlite::params![job.as_str(), state],
        )
        .unwrap();
        let accepted = retry(&f, &auth, state, &job).unwrap();
        assert_eq!(accepted.retry_of, Some(job), "{state}");
    }
    let source = canceled_source(&f, &auth, "chain-source");
    let first = retry(&f, &auth, "chain-1", &source).unwrap();
    f.store
        .cancel_execution_job(auth.clone(), first.job_id.clone())
        .unwrap();
    let second = retry(&f, &auth, "chain-2", &first.job_id).unwrap();
    assert_eq!(second.retry_of, Some(first.job_id.clone()));
    let (job, _, _) = job_row(&db, second.job_id.as_str());
    let (source_job, _, _) = job_row(&db, source.as_str());
    assert_eq!(job.4, source_job.4);
}

#[test]
fn committed_retry_survives_a_dropped_reply_and_a_restart() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let key = IdempotencyKey::parse(KEY).unwrap();
    let state = f
        .store
        .request(|reply| Command::ReadRetry(auth.clone(), key.clone(), source.clone(), reply))
        .unwrap();
    let prepared = retry::prepare_retry(&f.root, &auth, &key, &source, &prerequisites(&f), state);
    let (reply, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    f.store
        .sender
        .send(Command::FinishRetry(
            auth.clone(),
            key.clone(),
            source.clone(),
            Box::new(prepared),
            reply,
        ))
        .ok()
        .unwrap();
    let replay = retry(&f, &auth, KEY, &source).unwrap();
    assert!(replay.replayed);
    let Fixture {
        _parent,
        root,
        store,
        auth: submit,
        prepared,
    } = f;
    drop(store);
    let reopened = OwnedRoot::open(root.path(), RootPurpose::EngineData).unwrap();
    let lease = AuthorityLease::acquire(&reopened).unwrap();
    let f = Fixture {
        _parent,
        root,
        store: Store::open(reopened, lease, &CorePolicy::default()).unwrap(),
        auth: submit,
        prepared,
    };
    let after = retry(&f, &auth, KEY, &source).unwrap();
    assert_eq!(after, replay);
    assert_eq!(count(&db(&f), "SELECT count(*) FROM retry_bindings"), 1);
}

#[test]
fn a_source_change_between_read_and_finish_is_stale_and_rechecked() {
    let f = Fixture::new();
    let auth = authorize(&f);
    let source = canceled_source(&f, &auth, "source");
    let key = IdempotencyKey::parse(KEY).unwrap();
    let state = f
        .store
        .request(|reply| Command::ReadRetry(auth.clone(), key.clone(), source.clone(), reply))
        .unwrap();
    let prepared = retry::prepare_retry(&f.root, &auth, &key, &source, &prerequisites(&f), state);
    // Isolated offline change of a mutable source fact after the read.
    db(&f)
        .execute(
            "UPDATE job_execution SET cleanup_status='pending' WHERE job_id=?1",
            [source.as_str()],
        )
        .unwrap();
    let stale = f
        .store
        .request(|reply| {
            Command::FinishRetry(
                auth.clone(),
                key.clone(),
                source.clone(),
                Box::new(prepared),
                reply,
            )
        })
        .unwrap();
    assert!(stale.is_none());
    assert_eq!(
        retry(&f, &auth, KEY, &source).unwrap_err().code,
        ErrorCode::CleanupUnconfirmed
    );
}
